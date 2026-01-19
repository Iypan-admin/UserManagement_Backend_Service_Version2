const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// Default client (anon key) – for frontend or safe queries
const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_KEY // anon key
);

// Admin client (service role key) – for backend inserts, webhooks, storage, etc.
const supabaseAdmin = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY // service role key
);

module.exports = { supabase, supabaseAdmin };
