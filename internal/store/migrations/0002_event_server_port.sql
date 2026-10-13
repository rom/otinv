-- Events gained the port their session was served on. Direction describes a
-- single PDU and can invert mid-session, so this is what tells the inventory
-- which endpoint is the device.
ALTER TABLE events ADD COLUMN server_port INTEGER;
