local BasePlugin = require "kong.plugins.base_plugin"
local OidcHandler = BasePlugin:extend()
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")

OidcHandler.PRIORITY = 1000


function OidcHandler:new()
  OidcHandler.super.new(self, "oidc")
end

function OidcHandler:access(config)
  OidcHandler.super.access(self)
  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "OidcHandler ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "OidcHandler done")
end

function handle(oidcConfig)
  local user, access_token, id_token
  
  if oidcConfig.introspection_endpoint then
    user = introspect(oidcConfig)
  end

  if user == nil then
    local response = make_oidc(oidcConfig)
    if response then
      user = response.user
      access_token = response.access_token
      id_token = response.id_token
    end
  else
    access_token = utils.get_access_token()
  end

  if (not oidcConfig.disable_userinfo_header
      and user) then
    utils.injectUser(user, oidcConfig.userinfo_header_name)
    utils.injectGroups(user, oidcConfig.groups_claim)
  end
  if (not oidcConfig.disable_access_token_header
      and access_token) then
    utils.injectAccessToken(access_token, oidcConfig.access_token_header_name, oidcConfig.access_token_as_bearer)
  end
  if (not oidcConfig.disable_id_token_header
      and id_token) then
    utils.injectIDToken(id_token, oidcConfig.id_token_header_name)
  end
end

function make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "OidcHandler calling authenticate, requested path: " .. ngx.var.request_uri)
  local unauth_action = oidcConfig.unauth_action
  if unauth_action ~= "auth" then
    -- constant for resty.oidc library
    unauth_action = "deny"
  end
  local res, err = require("resty.openidc").authenticate(oidcConfig, ngx.var.request_uri, unauth_action)

  if err then
    if err == 'unauthorized request' then
      utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
    else
      if oidcConfig.recovery_page_path then
    	  ngx.log(ngx.DEBUG, "Redirecting to recovery page: " .. oidcConfig.recovery_page_path)
        ngx.redirect(oidcConfig.recovery_page_path)
      end
      utils.exit(ngx.HTTP_INTERNAL_SERVER_ERROR, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
    end
  end
  return res
end

function introspect(oidcConfig)
  if utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes" then
    local res, err = require("resty.openidc").introspect(oidcConfig)
    if err then
      if oidcConfig.bearer_only == "yes" then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. err .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, err, ngx.HTTP_UNAUTHORIZED)
      end
      return nil
    end
    ngx.log(ngx.DEBUG, "OidcHandler introspect succeeded, requested path: " .. ngx.var.request_uri)
    return res
  end
  return nil
end

return OidcHandler
