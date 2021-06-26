local ipairs = ipairs
local type = type
local encode_base64 = ngx.encode_base64
local string_format = string.format
local string_gsub = string.gsub
local tabel_insert = table.insert

local utils = require("orange.utils.utils")
local orange_db = require("orange.store.orange_db")
local judge_util = require("orange.utils.judge")
local handle_util = require("orange.utils.handle")
local BasePlugin = require("orange.plugins.base_handler")
local extractor_util = require("orange.utils.extractor")


-- @param author      rongxiang
-- @param version     2021-06
-- @param dscription  check sign when user send request
-- @return info   --403 message = "MISS headers['app_timestamp']!"
--403 message = "MISS headers['app_sign']!"
--403 message = "MISS headers['app_name']!"
--403 message = app_name .. " DON'T HAVE PERMISSION TO ACCESS THIS INTERFACE"
--403 message = "HEAD['sign'] ISN'T RIGHT, PLEASE CHECK IT."
-- 接口方式添加：
-- @use curl -i -X POST http://ip:8001/plugins -d "name=signature-to-esb" -d "config.keylist[1]={"$appname":"$key"}"


local function is_authorized(secretKey,requestParam,headers)
    --signature_name 为用户名
    --secretKey 为用户对应的密钥key

    local paramStr = ""

    --检查参数（用户名和密钥）
    if not secretKey then
        return false,'sig or secret key config error'
    end

    --验签逻辑
    local check_sig = function(secretKey)

        local app_timestamp = headers["app_timestamp"]
        local app_sign = headers["app_sign"]
        local app_name = headers["app_name"]
        --ngx.log(ngx.INFO, "[SignatureAuthHeader-app_sign] ",app_sign)
        --值校验
        if(app_timestamp==nil) then
            ngx.log(ngx.ERR,"MISS HEAD['dcap_timestamp']!")
            ngx.exit(tonumber(handle.code) or 403, { "MISS HEAD['dcap_timestamp']!" })
        elseif(app_sign==nil) then
            ngx.log(ngx.ERR,"MISS headers['app_sign']!")
            ngx.exit(tonumber(handle.code) or 403, { "MISS headers['app_sign']!" })
        elseif(app_name==nil) then
            ngx.log(ngx.ERR,"MISS headers['app_name']!")
            ngx.exit(tonumber(handle.code) or 403, { "MISS headers['app_name']!" })
        end

        --req_val 为请求中拼接的参数
        local req_val = {}
        --提取请求中所有参数
        for k,v in pairs(requestParam)do
            --get not nil value
            if(v ~= "" and v ~= true)then
                tabel_insert(req_val,k)
            end
        end
        --变量字典排序
        table.sort(req_val)
        --按照字典序拼接paramStr，例如：akauth&client=$UUID
        for k,v in pairs(req_val)do
            if(paramStr=="") then
                paramStr = paramStr .. v .. "=" .. requestParam[v]
            else
                paramStr = paramStr .. "&".. v .. "=" .. requestParam[v]
            end
        end

        --调用MD5函数
        local md5 = require("resty.md5")
        local md5 = md5:new()
        if not md5 then
            ngx.log(ngx.ERR,'server error exec md5:new faild')
            return false
        end
        --拼接时间字段和密钥
        paramStr = paramStr .. "&app_timestamp=" .. app_timestamp .."&secretKey=" .. secretKey
        ngx.log(ngx.INFO, "[SignatureAuthHeader-paramStr] ",paramStr)

        local ok = md5:update(paramStr)
        if not ok then
            ngx.log(ngx.INFO,"failed to add data")
            return
        end

        --MD5加密
        local str = require "resty.string"
        local calc_sig = str.to_hex(md5:final())
        ngx.log(ngx.INFO, "[SignatureAuthHeader-calc_sig] ",calc_sig)
        ngx.log(ngx.INFO, "[SignatureAuthHeader-app_sign] ",app_sign)
        --比较验签值
        return calc_sig == string.lower(app_sign)

    end

    return check_sig(secretKey)

end


local function filter_rules(sid, plugin, ngx_var_uri,requestParam,headers)
    local rules = orange_db.get_json(plugin .. ".selector." .. sid .. ".rules")
    if not rules or type(rules) ~= "table" or #rules <= 0 then
        return false
    end

    for i, rule in ipairs(rules) do
        if rule.enable == true then
            -- judge阶段
            local pass = judge_util.judge_rule(rule, plugin)

            -- handle阶段
            local handle = rule.handle or {}
            if pass then
                if handle.credentials then
                    if handle.log == true then
                        ngx.log(ngx.INFO, "[SignatureAuthHeader-Pass-Rule] ", rule.name, " uri:", ngx_var_uri)
                    end
                    local credentials = handle.credentials
                    local authorized = is_authorized(credentials.secretkey,requestParam,headers)
                    ngx.log(ngx.INFO, "[SignatureAuthHeader-authorized] ",authorized)
                    if authorized then
                        return true
                    else
                        ngx.exit(tonumber(handle.code) or 401)
                        return true
                    end
                else
                    if handle.log == true then
                        ngx.log(ngx.INFO, "[SignatureAuthHeader-Forbidden-Rule] ", rule.name, " uri:", ngx_var_uri)
                    end
                    ngx.exit(tonumber(handle.code) or 401)
                    return true
                end
            end
        end
    end

    return false
end


local SignatureAuthHeaderHandler = BasePlugin:extend()
SignatureAuthHeaderHandler.PRIORITY = 2000

function SignatureAuthHeaderHandler:new(store)
    SignatureAuthHeaderHandler.super.new(self, "signature_auth_header-plugin")
    self.store = store
end

function SignatureAuthHeaderHandler:access(conf)
    SignatureAuthHeaderHandler.super.access(self)

    local enable = orange_db.get("signature_auth_header.enable")
    local meta = orange_db.get_json("signature_auth_header.meta")
    local selectors = orange_db.get_json("signature_auth_header.selectors")
    local ordered_selectors = meta and meta.selectors

    --获取请求的query信息
    local requestParam = ngx.req.get_uri_args()
    --获取请求的header信息
    local headers = ngx.req.get_headers()

    if not enable or enable ~= true or not meta or not ordered_selectors or not selectors then
        return
    end

    local ngx_var_uri = ngx.var.uri

    for i, sid in ipairs(ordered_selectors) do
        ngx.log(ngx.INFO, "==[SignatureAuthHeader][PASS THROUGH SELECTOR:", sid, "]")
        local selector = selectors[sid]
        if selector and selector.enable == true then
            local selector_pass
            if selector.type == 0 then -- 全流量选择器
                selector_pass = true
            else
                selector_pass = judge_util.judge_selector(selector, "signature_auth_header")-- selector judge
            end

            if selector_pass then
                if selector.handle and selector.handle.log == true then
                    ngx.log(ngx.INFO, "[SignatureAuthHeader][PASS-SELECTOR:", sid, "] ", ngx_var_uri)
                end

                local stop = filter_rules(sid, "signature_auth_header", ngx_var_uri,requestParam,headers)
                local selector_continue = selector.handle and selector.handle.continue
                if stop or selector_continue then -- 不再执行此插件其他逻辑
                    return
                end
            else
                if selector.handle and selector.handle.log == true then
                    ngx.log(ngx.INFO, "[SignatureAuthHeader][NOT-PASS-SELECTOR:", sid, "] ", ngx_var_uri)
                end
            end
        end
    end

end

return SignatureAuthHeaderHandler
