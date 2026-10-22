-- Card: Storage, the fullest devices. Appended to storage_devices.sql.
SELECT m.serial,
       COALESCE(NULLIF(inv.data->>'device_name', ''), NULLIF(inv.data->>'deviceName', ''),
                NULLIF(m.device_name, ''), m.serial) AS name,
       m.platform, m.total_bytes, m.free_bytes, m.free_ratio
FROM measured m
LEFT JOIN inventory inv ON inv.device_id = m.id
ORDER BY m.free_ratio ASC, m.serial COLLATE "C"
LIMIT %(limit)s
