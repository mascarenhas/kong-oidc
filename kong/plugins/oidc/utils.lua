local cjson = require("cjson")

local M = {}

local function parseFilters(csvFilters)
  local filters = {}
  if (not (csvFilters == nil)) and (not (csvFilters == ",")) then
    for pattern in string.gmatch(csvFilters, "[^,]+") do
      table.insert(filters, pattern)
    end
  end
  return filters
end

local function formatAsBearerToken(token)
  return "Bearer " .. token
end

function M.get_redirect_uri(ngx)
  local function drop_query()
    local uri = ngx.var.request_uri
    local x = uri:find("?")
    if x then
      return uri:sub(1, x - 1)
    else
      return uri
    end
  end

  local function tackle_slash(path)
    local args = ngx.req.get_uri_args()
    if args and args.code then
      return path
    elseif path == "/" then
      return "/cb"
    elseif path:sub(-1) == "/" then
      return path:sub(1, -2)
    else
      return path .. "/"
    end
  end

  return tackle_slash(drop_query())
end

function M.get_options(config, ngx)
  return {
    client_id = config.client_id,
    client_secret = config.client_secret,
    discovery = config.discovery,
    introspection_endpoint = config.introspection_endpoint,
    timeout = config.timeout,
    introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
    bearer_only = config.bearer_only,
    realm = config.realm,
    redirect_uri = config.redirect_uri or M.get_redirect_uri(ngx),
    redirect_uri_scheme = config.redirect_uri_scheme,
    scope = config.scope,
    response_type = config.response_type,
    ssl_verify = config.ssl_verify,
    token_endpoint_auth_method = config.token_endpoint_auth_method,
    recovery_page_path = config.recovery_page_path,
    filters = parseFilters((config.filters or "") .. "," .. (config.ignore_auth_filters or "")),
    logout_path = config.logout_path,
    redirect_after_logout_uri = config.redirect_after_logout_uri,
    unauth_action = config.unauth_action,
    userinfo_header_name = config.userinfo_header_name,
    id_token_header_name = config.id_token_header_name,
    access_token_header_name = config.access_token_header_name,
    access_token_as_bearer = config.access_token_as_bearer == "yes",
    disable_userinfo_header = config.disable_userinfo_header == "yes",
    disable_id_token_header = config.disable_id_token_header == "yes",
    disable_access_token_header = config.disable_access_token_header == "yes",
    groups_claim = config.groups_claim == "groups"
  }
end

function M.exit(httpStatusCode, message, ngxCode)
  ngx.status = httpStatusCode
  ngx.say(message)
  ngx.exit(ngxCode)
end

function M.injectAccessToken(accessToken, headerName, bearerToken)
  ngx.log(ngx.DEBUG, "Injecting " .. headerName)
  local token = accessToken
  if (bearerToken) then
    token = formatAsBearerToken(token)
  end
  ngx.req.set_header(headerName, token)
end

function M.injectIDToken(idToken, headerName)
  ngx.log(ngx.DEBUG, "Injecting " .. headerName)
  local tokenStr = cjson.encode(idToken)
  ngx.req.set_header(headerName, ngx.encode_base64(tokenStr))
end

function M.injectUser(user, headerName)
  local email = user.email
  local username = user.preferred_username or (email and email:match("^([^@]+)") or nil)
  ngx.ctx.authenticated_credential = {
    id = user.sub,
    username = username
  }
  local userinfo = cjson.encode(user)
  ngx.log(ngx.DEBUG, "Injecting " .. headerName)
  ngx.req.set_header(headerName, ngx.encode_base64(userinfo))
  ngx.log(ngx.DEBUG, "Injecting X-Forwarded-User")
  ngx.req.set_header('X-Forwarded-User', username)
  ngx.log(ngx.DEBUG, "Injecting X-Forwarded-Email")
  ngx.req.set_header('X-Forwarded-Email', user.email)
  if user.preferred_username then
    ngx.log(ngx.DEBUG, "Injecting X-Forwarded-Preferred-Username")
    ngx.req.set_header('X-Forwarded-Preferred-Username', user.preferred_username)
  end
end

function M.injectGroups(user, claim)
  if user[claim] ~= nil then
    kong.ctx.shared.authenticated_groups = user[claim]
  end
end

function M.has_bearer_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header then
    local divider = header:find(' ')
    if divider and string.lower(header:sub(0, divider-1)) == string.lower("Bearer") then
      return true
    end
  end
  return false
end

function M.get_access_token()
  local header = ngx.req.get_headers()['Authorization']
  if header then
    local divider = header:find(' ')
    if divider and string.lower(header:sub(0, divider-1)) == string.lower("Bearer") then
      return string.sub(header, divider+1)
    end
  end
  return nil
end

return M
