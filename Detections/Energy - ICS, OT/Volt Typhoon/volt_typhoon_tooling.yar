/*
   Volt Typhoon (VOLTZITE) — tooling YARA
   Sources: CISA AA24-038A / AA23-144A; Microsoft Volt Typhoon LOTL blog.

   *** HONEST LIMITATION — READ THIS ***
   Volt Typhoon is a LIVING-OFF-THE-LAND actor. On victim endpoints there is
   effectively NO signature malware to match — they use built-in Windows tools
   (netsh, ntdsutil, wmic, PowerShell, rundll32/comsvcs) and valid credentials.
   The KV-botnet implant runs on compromised SOHO/edge ROUTERS, not your Windows
   estate. Therefore YARA is the WEAKEST detection leg for this actor:
   the real coverage is the behavioral SPL/KQL in this folder.

   What YARA *can* do here:
     1. Exact-hash match the custom Fast Reverse Proxy (FRP) builds Microsoft/
        CISA published (reliable, but you must paste the hashes).
     2. Heuristically flag FRP tooling generally — but FRP is open-source and
        dual-use, so this is HUNT-ONLY / high false-positive on hosts where
        FRP is not expected.

   Requires the YARA 'hash' module for volt_typhoon_custom_frp_hashes.
*/

import "hash"

rule volt_typhoon_custom_frp_hashes
{
    meta:
        description = "Volt Typhoon custom FRP/Impacket builds — exact hashes. ADD VERIFIED SHA-256 VALUES from the Microsoft/CISA Volt Typhoon reporting before relying on this rule."
        author      = Eliza / eliza-commit5
        date        = "2026-06-11"
        reference   = "https://www.microsoft.com/en-us/security/blog/2023/05/24/volt-typhoon-targets-us-critical-infrastructure-with-living-off-the-land-techniques/"
        actor       = "Volt Typhoon (VOLTZITE)"
        confidence  = "high"
        tlp         = "CLEAR"
    condition:
        // <-- ADD VERIFIED HASHES: replace the placeholder with real SHA-256s.
        // Intentionally false so the rule compiles but never fires until populated.
        hash.sha256(0, filesize) == "0000000000000000000000000000000000000000000000000000000000000000"
}

rule frp_fast_reverse_proxy_tooling_huntonly
{
    meta:
        description = "Fast Reverse Proxy (FRP) tooling — used by Volt Typhoon for C2 over proxy. DUAL-USE / HIGH FALSE-POSITIVE: FRP is legitimate open-source software. Hunt-only on hosts where FRP is not sanctioned; do NOT auto-block."
        author      = Eliza / eliza-commit5
        date        = "2026-06-11"
        reference   = "https://github.com/fatedier/frp"
        actor       = "Volt Typhoon (VOLTZITE) — tooling, not exclusive"
        confidence  = "low"
        tlp         = "CLEAR"
    strings:
        $import   = "github.com/fatedier/frp" ascii
        $frpc     = "frpc" ascii
        $frps     = "frps" ascii
        $cfg_addr = "server_addr" ascii
        $cfg_tok  = "privilege_token" ascii
        $cfg_sec  = "[common]" ascii
        $go       = "Go build ID:" ascii
    condition:
        ( uint16(0) == 0x5a4d or uint32(0) == 0x464c457f )   // PE or ELF
        and filesize < 30MB
        and (
            $import                                          // strongest single signal
            or ( $go and 1 of ($frp*) and 1 of ($cfg_*) )    // Go FRP build heuristic
        )
}
