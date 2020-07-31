-- As you can see, the config file is just a Lua script.

-- The cloud configuration table.
cloud = {

	-- The directory where the users will be stored.
	users_directory = "users",

	-- The directory where the users' files' metadata will be stored.
	nodes_head_directory = "nodes_head",

	-- The directory where the users' files' data will be stored.
	nodes_data_directory = "nodes_data",

	-- The file where the server will write its logs to. Could be omitten, default value is nil, which means that no logging will be done.
	access_log = "access.log",

	-- To made user registering possible, you need to create a invitation codes and send them to the people which you want to register.
	-- The invitation codes should be put in this file.
	invites_file = "invites.txt",
	-- The invitation codes are one-time use, so the used invites will be erased from this file automatically.

	-- Network buffer size (in bytes). Default is 1024 * 1024 = 1 MiB.
	net_buffer_size = 1024 * 1024,
	
	-- Disk buffer size (in bytes). Default is 1024 * 640 = 640 KiB.
	data_buffer_size = 1024 * 640,

}


-- Launcher configuration table. Could be omitten, then all the options will be set on their defaults.
launcher = {

	-- The port which the server will run on. Default is 909.
	server_port = 909,

	-- You could run server on bare TCP or with SSL, the following table is here to set up the SSL options.
	-- To enable SSL, put your SSL certificate and private key in the working directory, then uncomment 'ssl' table (just put the space between '-' and '[' in the next line) and set up the options for appropriate values.
	--[[
	ssl = {

		-- SSL certificate
		cert = "cert.pem",
		
		-- SSL private key
	 	key = "key.pem",

		-- SSL private key password. Can be omitten, default is nil, which means that the password will be prompted (if necessary)
		-- password = "PASSWORD",

	},
	--]]
}
