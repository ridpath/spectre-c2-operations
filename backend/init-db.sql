-- Spectre C2 Database Initialization Script
-- This script runs automatically when the PostgreSQL container first starts

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create database if it doesn't exist (this runs before connection to the app DB)
SELECT 'CREATE DATABASE spectre_c2'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'spectre_c2')\gexec

-- Set default search path
SET search_path TO public;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE spectre_c2 TO spectre;

-- Performance tuning
ALTER DATABASE spectre_c2 SET random_page_cost = 1.1;
ALTER DATABASE spectre_c2 SET effective_cache_size = '4GB';
ALTER DATABASE spectre_c2 SET shared_buffers = '1GB';
ALTER DATABASE spectre_c2 SET work_mem = '16MB';
ALTER DATABASE spectre_c2 SET maintenance_work_mem = '256MB';

-- Create schema for partitioning if needed
CREATE SCHEMA IF NOT EXISTS archive;
GRANT ALL ON SCHEMA archive TO spectre;

-- Log completion
DO $$
BEGIN
  RAISE NOTICE 'Spectre C2 database initialized successfully';
END $$;
