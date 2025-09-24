// Server-side Supabase client example
// Usage: set SUPABASE_KEY in environment (dot env or hosting provider secrets)
const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = 'https://tkufqhgurweuufqnwdik.supabase.co';
const supabaseKey = process.env.SUPABASE_KEY; // set this securely in your environment

if (!supabaseKey) {
  console.warn('Warning: SUPABASE_KEY is not set. Server-side Supabase operations will fail.');
}

const supabase = createClient(supabaseUrl, supabaseKey);

module.exports = supabase;
