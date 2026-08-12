DROP INDEX requests_one_active_per_device;
CREATE UNIQUE INDEX requests_one_active_per_device ON requests (device_id)
    WHERE state IN ('planning', 'pending', 'approved', 'executing', 'recovery_required');
