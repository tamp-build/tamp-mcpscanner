//////////////////////////////////////////
// Secrets Exposure Detection Rule — .NET-tuned overlay
//
// Derived from Cisco's credential_harvesting.yara (Apache-2.0; see NOTICE).
// The ONLY change from the base rule is the $dotnet_config_idioms negative
// guard: the base's $credential_file_extensions matches ".config", and
// $access_actions_words matches "read"/"load"/"open", so a .NET tool whose
// description legitimately mentions reading app.config / web.config /
// appsettings.json via IConfiguration/ConfigurationManager was flagged as
// credential harvesting. That is a stack-idiom false positive, not a finding.
// Everything else is byte-identical to the base rule, so detection is otherwise
// unchanged. Rule name is kept so this REPLACES the base when --rules-path is
// the .NET pack. See docs/stack-rules.md.
//////////////////////////////////////////

rule credential_harvesting{

    meta:
        author = "Cisco; .NET tuning by Tamp Project"
        description = "Detects potential exposure of sensitive information like API keys, passwords, tokens, and certificates (.NET-idiom tuned)"
        classification = "harmful"
        threat_type = "CREDENTIAL HARVESTING"

    strings:

        ////////////////////////////////////////////////
        //// All action words
        ////////////////////////////////////////////////

        // File access action words (to combine with credential file extensions)
        $access_actions_words = /\b(open|read|cat|display|fetch|retrieve|access|load|download|copy|steal|grab|extract|dump|leak|exfiltrate|send|upload|share|expose|reveal|dump|harvest)\b/i

        // File system operations (to combine with credential file extensions)
        $file_system_operations = /\b(ls|dir|find|locate|search|grep|awk|sed|hexdump|xxd|head|tail|less|more|strings|file|stat|chmod|chown|mv|cp|rm|del)\b/i

        // Network/transfer actions (to combine with credential file extensions)
        $transfer_actions = /\b(curl|wget|scp|rsync|ftp|sftp|ssh|nc|netcat|base64|encode|decode|compress|zip|tar|gzip|unzip)\b/i

        ////////////////////////////////////////////////
        //// All Content-key based credential patterns
        ////////////////////////////////////////////////

        $api_credentials = /\b[Aa][Pp][Ii][\_\-]?[Kk][Ee][Yy][^A-Za-z0-9\n]{1,24}[A-Za-z0-9_\-]{16,512}|[Bb]earer\s+[A-Za-z0-9\-_]{16,}|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{48}/

        // SSH keys, certificates and credential file content (consolidated)
        $key_certificate_content = /(-----BEGIN (RSA |OPENSSH |EC |DSA |CERTIFICATE|PRIVATE KEY|ENCRYPTED PRIVATE KEY)-----|ssh-(rsa|ed25519)\s+[A-Za-z0-9+\/=]{8})/

        // AI/ML model API key names (prone to false positives alone)
        $ai_model_credential_names = /\b(OPENAI_API_KEY|ANTHROPIC_API_KEY|CLAUDE_API_KEY|GOOGLE_AI_KEY|GEMINI_API_KEY|COHERE_API_KEY|HUGGINGFACE_TOKEN|HF_TOKEN|TOGETHER_API_KEY|REPLICATE_API_TOKEN|MISTRAL_API_KEY|PALM_API_KEY|BARD_API_KEY|STABILITY_API_KEY|MIDJOURNEY_TOKEN|RUNWAY_API_KEY|ELEVENLABS_API_KEY|DEEPGRAM_API_KEY|AZURE_OPENAI_KEY|AZURE_COGNITIVE_KEY|BEDROCK_ACCESS_KEY)\b/

        // Environment variable patterns for secrets
        $env_secret_vars = /\b(AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY)|(GITHUB|DISCORD|BITBUCKET|SLACK|JENKINS_API|CLOUDFLARE_API|DIGITALOCEAN|LINODE)_TOKEN|DOCKER_PASSWORD|STRIPE_SECRET_KEY|PAYPAL_CLIENT_SECRET|FACEBOOK_APP_SECRET|TWITTER_API_SECRET|LINKEDIN_CLIENT_SECRET|ZOOM_API_SECRET|SENDGRID_API_KEY|MAILGUN_API_KEY|HEROKU_API_KEY|VULTR_API_KEY|JWT_SECRET|SESSION_SECRET|COOKIE_SECRET)\b/

        // Database connection strings and credentials
        $database_credentials = /\b((DATABASE|DB|MONGODB|REDIS|POSTGRES|MYSQL|PGSQL)_PASSWORD)(\b|\_)/

        // Environment variable access methods
        $env_access_methods = /\b(process\.env\.|os\.environ|getenv\s*\()/

        ////////////////////////////////////////////////
        //// All file/directory-based credential patterns
        ////////////////////////////////////////////////

        $sensitive_file_patterns = /\b(\*\.env|\*\.pem|\*\.key|\*credentials\*|\*secrets?\*|\*passwords?\*|\*tokens?\*|\*private[_-]?keys?\*)\b/i

        $env_exfil = /\b(environment|env)\s+(variables?|vars?)?\s*(collect|gather|send|upload|transmit|dump|extract)/i

        $source_exfil = /\b(source\s+code|codebase|repository|repo)\s*(upload|send|transmit|copy|sync|backup)\s+(to\s+)?(external|remote)/i

        $credential_directories = /[\/\\]\.(ssh|aws|kube)[\/\\]/

        $credential_filenames = /\b(id_rsa|id_dsa|id_ecdsa|id_ed25519|aws_key|aws_secret|gcloud_key|azure_key|private_key|authorized_keys|known_hosts|credentials\.json|service_account\.json|wallet\.dat)\b/i

        $specific_credential_files = /\b(aws_credentials|gcloud|docker\/config\.json|\.netrc|\.pgpass|\/proc\/\d+\/|\.dmp|\.dump|core\.|memory\.dat|process\.mem)\b/i

        $credential_file_extensions = /\.(keystore|passwd|shadow|config|env|credential|secret|token|private|pub|rsa|dsa|ecdsa|ed25519|pem|crt|cer|key|p12|pfx|jks)\b/

        $leak_param  = /\b(leak|exfiltrate|export|dump) [^\n]{0,40}?(parameter|context|credentials??|keys??|tokens??|secrets??|files?? [^.\n;]{0,40}?(credentials??|keys??|tokens??|secrets??|passwords??))\b/i

        $base64_credential_encoding = /\b(base64\s+encode [^\n]*credentials?|concatenate [^\n]*conversation\s+history)\b/i

        $mcp_credential_patterns = /\b(claude_desktop_config\.json|~\/\.cursor\/logs\/conversations|plaintext[^\n]*api[^\n]*key|-rw-r--r--[^\n]*password)\b/i

        $whatsapp_exploit = /\b(_get_all_messages[^\n]*messages\.db|forward[^\n]*message[^\n]*proxy[^\n]*number|whatsapp[^\n]*message[^\n]*history|contact[^\n]*list[^\n]*exfiltrat|reprogram[^\n]*agent[^\n]*interaction)\b/i

        $generic_config_ops = /(get_env|set_env|read_config|write_config|config_file|settings_file|env_file)/
        $template_indicators = /(\bYOUR_API_KEY|\bREPLACE_WITH|\bINSERT_KEY|\.example|\.sample|\.template)/
        $negated_disclosure = /\b(no\s+(secrets?|credentials?|tokens?|keys?|passwords?)|without\s+(secrets?|credentials?|tokens?|keys?|passwords?)|(secrets?|credentials?|tokens?|keys?|passwords?)-free)\b/i

        //////////////////////////////////////////////////////////////////
        //// .NET stack idioms — legitimate configuration surface that the
        //// base rule mistakes for credential access. app.config / web.config
        //// (the ".config" extension), appsettings[.*].json, and the standard
        //// configuration/connection-string APIs. Narrow and specific so it
        //// only suppresses real .NET config phrasing, not genuine secrets.
        //////////////////////////////////////////////////////////////////
        $dotnet_config_idioms = /\b(app\.config|web\.config|appsettings(\.[A-Za-z]+)?\.json|IConfiguration|ConfigurationManager|ConfigurationBuilder|IOptions(Monitor|Snapshot)?|GetConnectionString|AddJsonFile|AddUserSecrets|builder\.Configuration)\b/

    condition:

        // API credentials
        ($api_credentials and ($transfer_actions or $file_system_operations or $access_actions_words) and not $template_indicators and not $generic_config_ops) or

        // File-based credential patterns with suspicious actions.
        // .NET-tuned: also suppressed when the description is .NET config phrasing.
        (($credential_directories or $credential_filenames or $specific_credential_files or $credential_file_extensions) and ($transfer_actions or $file_system_operations or $access_actions_words) and not $generic_config_ops and not $dotnet_config_idioms) or

        // Content-based credential patterns with suspicious actions
        (($key_certificate_content or $ai_model_credential_names or $env_secret_vars or $database_credentials or $env_access_methods) and ($transfer_actions or $file_system_operations or $access_actions_words) and not $generic_config_ops) or

        // Sensitive data targeting patterns
        (($sensitive_file_patterns or $env_exfil or $source_exfil) and ($transfer_actions or $file_system_operations or $access_actions_words) and not $generic_config_ops) or

        // Exfiltration attempts
        ($leak_param and not $generic_config_ops and
          (for any i in (1..#leak_param) :
            (not (for any j in (1..#negated_disclosure) :
              ((@negated_disclosure[j] >= @leak_param[i]) and (@negated_disclosure[j] < @leak_param[i] + !leak_param[i])))))) or

        // Base64 credential encoding
        $base64_credential_encoding or

        // MCP-specific credential patterns
        $mcp_credential_patterns or

        // WhatsApp exploit
        $whatsapp_exploit
}
