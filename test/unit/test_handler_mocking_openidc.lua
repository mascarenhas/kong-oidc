local lu = require("luaunit")
TestHandler = require("test.unit.mockable_case"):extend()


function TestHandler:setUp()
  TestHandler.super:setUp()

  package.loaded["resty.openidc"] = nil
  self.module_resty = {openidc = {
    authenticate = function(...) return {}, nil end }
  }
  package.preload["resty.openidc"] = function()
    return self.module_resty.openidc
  end

  self.handler = require("kong.plugins.oidc.handler")()
end

function TestHandler:tearDown()
  TestHandler.super:tearDown()
end

function TestHandler:test_authenticate_ok_no_userinfo()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, false
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
end

function TestHandler:test_authenticate_ok_with_userinfo()
  self.module_resty.openidc.authenticate = function(opts)
    return {user = {sub = "sub"}}, false
  end
  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end
  
  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({userinfo_header_name = 'X-Userinfo'})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertEquals(ngx.ctx.authenticated_credential.id, "sub")
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_authenticate_ok_with_userinfo_and_forwarded_headers()
  self.module_resty.openidc.authenticate = function(opts)
    return {user = {sub = "sub", email = "user@example.com"}}, false
  end
  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end
  
  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({userinfo_header_name = 'X-Userinfo'})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertEquals(ngx.ctx.authenticated_credential.id, "sub")
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
  lu.assertEquals(headers['X-Forwarded-User'], 'user')
  lu.assertEquals(headers['X-Forwarded-Email'], 'user@example.com')
  lu.assertEquals(headers['X-Forwarded-Preferred-Username'], nil)
end

function TestHandler:test_authenticate_ok_with_userinfo_and_forwarded_headers_with_preferred_username()
  self.module_resty.openidc.authenticate = function(opts)
    return {user = {sub = "sub", preferred_username = "username", email = "user@example.com"}}, false
  end
  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end
  
  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({userinfo_header_name = 'X-Userinfo'})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertEquals(ngx.ctx.authenticated_credential.id, "sub")
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
  lu.assertEquals(headers['X-Forwarded-User'], 'username')
  lu.assertEquals(headers['X-Forwarded-Email'], 'user@example.com')
  lu.assertEquals(headers['X-Forwarded-Preferred-Username'], 'username')
end

function TestHandler:test_authenticate_ok_with_no_accesstoken()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, true
  end
  
  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertNil(headers['X-Access-Token'])
end

function TestHandler:test_authenticate_ok_with_accesstoken()
  self.module_resty.openidc.authenticate = function(opts)
    return {access_token = "ACCESS_TOKEN"}, true
  end
  
  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({access_token_header_name = 'X-Access-Token'})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertEquals(headers['X-Access-Token'], "ACCESS_TOKEN")
end

function TestHandler:test_authenticate_ok_with_no_idtoken()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, true
  end
  
  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertNil(headers['X-ID-Token'])
end

function TestHandler:test_authenticate_ok_with_idtoken()
  self.module_resty.openidc.authenticate = function(opts)
    return {id_token = {sub = "sub"}}, true
  end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end
  
  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({id_token_header_name = 'X-ID-Token'})
  lu.assertTrue(self:log_contains("calling authenticate"))
  lu.assertEquals(headers['X-ID-Token'], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_authenticate_nok_no_recovery()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, true
  end

  self.handler:access({})
  lu.assertTrue(self:log_contains("calling authenticate"))
end

function TestHandler:test_authenticate_nok_deny()
  self.module_resty.openidc.authenticate = function(opts)
    if opts.unauth_action == "deny" then
		return {}, "unauthorized request"
	end
	return {}, true
  end

  self.handler:access({unauth_action = "deny"})
  lu.assertEquals(ngx.status, ngx.HTTP_UNAUTHORIZED)
end

function TestHandler:test_authenticate_nok_with_recovery()
  self.module_resty.openidc.authenticate = function(opts)
    return {}, true
  end

  self.handler:access({recovery_page_path = "x"})
  lu.assertTrue(self:log_contains("recovery page"))
end

function TestHandler:test_introspect_ok_no_userinfo()
  self.module_resty.openidc.introspect = function(opts)
    return false, false
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  self.handler:access({introspection_endpoint = "x", access_token_header_name = "X-Access-Token"})
  lu.assertTrue(self:log_contains("introspect succeeded"))
end

function TestHandler:test_introspect_ok_with_userinfo()
  self.module_resty.openidc.introspect = function(opts)
    return {}, false
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end

  self.handler:access({introspection_endpoint = "x", access_token_header_name = "X-Access-Token", userinfo_header_name = "X-Userinfo"})
  lu.assertTrue(self:log_contains("introspect succeeded"))
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_bearer_only_with_good_token()
  self.module_resty.openidc.introspect = function(opts)
    return {sub = "sub"}, false
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  ngx.encode_base64 = function(x)
    return "eyJzdWIiOiJzdWIifQ=="
  end

  local headers = {}
  ngx.req.set_header = function(h, v)
    headers[h] = v
  end
  self.handler:access({introspection_endpoint = "x", access_token_header_name = "X-Access-Token", bearer_only = "yes", realm = "kong", userinfo_header_name = "X-Userinfo"})

  lu.assertTrue(self:log_contains("introspect succeeded"))
  lu.assertEquals(headers['X-Userinfo'], "eyJzdWIiOiJzdWIifQ==")
end

function TestHandler:test_bearer_only_with_bad_token()
  self.module_resty.openidc.introspect = function(opts)
    return {}, "validation failed"
  end
  ngx.req.get_headers = function() return {Authorization = "Bearer xxx"} end

  self.handler:access({introspection_endpoint = "x", bearer_only = "yes", realm = "kong", userinfo_header_name = 'X-Userinfo'})

  lu.assertEquals(ngx.header["WWW-Authenticate"], 'Bearer realm="kong",error="validation failed"')
  lu.assertEquals(ngx.status, ngx.HTTP_UNAUTHORIZED)
  lu.assertFalse(self:log_contains("introspect succeeded"))
end

lu.run()


