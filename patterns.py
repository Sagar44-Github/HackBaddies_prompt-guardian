import re

# Each tuple: (regex_pattern, attack_type_name, risk_weight_from_0_to_1)
INJECTION_PATTERNS = [

    # ── Instruction Override ──────────────────────────────────────────────────
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|directives?|prompts?|context)",
     "instruction_override", 0.95),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|rules?|directives?|prompts?|context|training)",
     "instruction_override", 0.90),
    (r"forget\s+(everything|all|what)\s+(you|i|we)\s+(were|have|told|know|learned|trained|been)",
     "instruction_override", 0.90),
    (r"(override|bypass)\s+(your\s+)?(instructions?|rules?|training|guidelines?|directives?|programming)",
     "instruction_override", 0.92),
    (r"do\s+not\s+follow\s+(your\s+)?(previous|prior|original|system)\s+(instructions?|prompt|rules?)",
     "instruction_override", 0.88),
    (r"new\s+(system\s+)?(primary\s+)?instructions?\s*:",
     "instruction_override", 0.80),
    (r"new\s+(system\s+)?prompt\s+(that\s+)?(overrides?|replaces?|supersedes?)",
     "instruction_override", 0.89),
    (r"from\s+now\s+on[,\s]+(ignore|forget|disregard|stop\s+following|do\s+not\s+follow)",
     "instruction_override", 0.85),
    (r"set\s+aside\s+(everything|your|all)\s*(instructions?|rules?|training|guidelines?)?",
     "instruction_override", 0.84),
    (r"(clear|reset|wipe)\s+(your\s+)?(memory|context|instructions?|training|mind)",
     "instruction_override", 0.86),
    (r"start\s+(fresh|over|from\s+scratch)\s+(and\s+)?(ignore|without|forget)",
     "instruction_override", 0.83),
    (r"your\s+(real|actual|true|correct)\s+instructions?\s+(are|is|say|state)\s*:",
     "instruction_override", 0.88),
    (r"these\s+instructions?\s+(supersede|override|replace|take\s+priority\s+over)",
     "instruction_override", 0.90),
    (r"(discard|throw\s+away|delete|remove)\s+(all\s+)?(your\s+)?(previous\s+)?(instructions?|context|rules?|training)",
     "instruction_override", 0.87),
    (r"(stop|cease)\s+(following|obeying|adhering\s+to)\s+(your\s+)?(instructions?|rules?|guidelines?)",
     "instruction_override", 0.86),
    (r"i\s+(am|will\s+be)\s+(now\s+)?(giving|providing)\s+(you\s+)?(new|updated|different)\s+(instructions?|rules?|directives?)",
     "instruction_override", 0.82),

    # ── Jailbreak Attempts ────────────────────────────────────────────────────
    (r"\bDAN\b",
     "jailbreak", 0.95),
    (r"do\s+anything\s+now",
     "jailbreak", 0.92),
    (r"developer\s+mode",
     "jailbreak", 0.90),
    (r"\bjailbreak\s*(mode|prompt|this|yourself)?",
     "jailbreak", 0.95),
    (r"(no|without)\s+(any\s+)?(restrictions?|limits?|filters?|guidelines?|safety|censorship)",
     "jailbreak", 0.83),
    (r"bypass\s+(your\s+)?(safety|content|ethical|moral)?\s*(filters?|restrictions?|guidelines?|rules?)",
     "jailbreak", 0.92),
    (r"(evil|opposite|dark|unfiltered|unrestricted|uncensored)\s+(mode|version|ai|bot|gpt|assistant|model)",
     "jailbreak", 0.90),
    (r"disable\s+(your\s+)?(safety|ethical|moral)\s*(guidelines?|filters?|training)?",
     "jailbreak", 0.88),
    (r"(you\s+are|act\s+as|pretend\s+(you\s+are|to\s+be))\s+(dan|evil|unrestricted|unfiltered|uncensored)",
     "jailbreak", 0.96),
    (r"as\s+an?\s+(uncensored|unfiltered|unrestricted)\s+(ai|assistant|model|chatbot)",
     "jailbreak", 0.91),
    (r"hypothetically\s+(if|speaking|assuming)\s+(you\s+had\s+no|there\s+were\s+no|without)",
     "jailbreak", 0.79),
    (r"simulate\s+(an?\s+)?(ai|assistant|chatbot)\s+(with\s+)?(no|without)\s+(restrictions?|filters?|rules?)",
     "jailbreak", 0.88),
    (r"grandma\s*(exploit|trick|jailbreak|method)?",
     "jailbreak", 0.70),
    (r"\b(STAN|DUDE|AIM|KEVIN|ANTI[\s-]?DAN)\b",
     "jailbreak", 0.93),
    (r"(god|chaos|anarchy|sudo|admin|root|omega|ultra|turbo)\s+mode",
     "jailbreak", 0.88),
    (r"(opposite|contrary|reverse|anti)\s+(mode|day|world|universe)",
     "jailbreak", 0.82),
    (r"(maintenance|debug|diagnostic|test|safe)\s+mode\s+(enabled|on|activated|unlocked)",
     "jailbreak", 0.85),
    (r"you\s+have\s+been\s+(updated|upgraded|reprogrammed|patched|modified)\s+to\s+(allow|permit|enable|support)",
     "jailbreak", 0.88),
    (r"(unlock|enable|activate|turn\s+on)\s+(your\s+)?(hidden|secret|advanced|unrestricted)\s+(capabilities?|features?|mode|functions?)",
     "jailbreak", 0.87),
    (r"(token\s+budget|context\s+limit)\s+(bypass|exploit|trick|hack)",
     "jailbreak", 0.85),
    (r"always\s+(respond|answer|reply)\s+(with|as\s+if)\s+(you\s+have\s+no|without\s+any)\s+(restrictions?|filters?)",
     "jailbreak", 0.89),
    (r"you\s+(must|have\s+to|should|will)\s+(never|not)\s+(refuse|decline|say\s+no|reject)",
     "jailbreak", 0.84),

    # ── Prompt Extraction ─────────────────────────────────────────────────────
    (r"(reveal|show|print|output|display|expose|repeat)\s+(your\s+)?(full\s+)?(system\s+prompt|hidden\s+(prompt|instructions?)|initial\s+prompt|original\s+prompt)",
     "prompt_extraction", 0.95),
    (r"(print|repeat|output)\s+(everything|all(\s+text)?)\s+(above|before|prior)",
     "prompt_extraction", 0.92),
    (r"repeat\s+(everything|all|the\s+text|verbatim)\s+(above|before|from\s+the\s+(start|beginning))",
     "prompt_extraction", 0.88),
    (r"what\s+(are|were)\s+your\s+(exact\s+)?(initial|original|starting|system)\s+(instructions?|directives?|rules?|prompt)",
     "prompt_extraction", 0.85),
    (r"(output|write|show)\s+(your\s+)?(full\s+)?(system\s+)?instructions?\s+(verbatim|exactly|word\s+for\s+word)",
     "prompt_extraction", 0.90),
    (r"(tell|show)\s+me\s+(what|everything)\s+(you\s+were\s+told|your\s+(initial|starting)\s+prompt)",
     "prompt_extraction", 0.85),
    (r"ignore\s+.*\s+and\s+(instead\s+)?(print|output|reveal|show|repeat)\s+(your\s+)?(prompt|instructions?)",
     "prompt_extraction", 0.93),
    (r"(summarize|describe|paraphrase)\s+(your\s+)?(system\s+)?(prompt|instructions?|context|directives?)",
     "prompt_extraction", 0.82),
    (r"what\s+(is|was)\s+the\s+(first|last|opening|closing)\s+(word|line|sentence|paragraph)\s+(of\s+)?(your\s+)?(prompt|instructions?|context)",
     "prompt_extraction", 0.86),
    (r"(copy|paste|reproduce|dump)\s+(your\s+)?(entire\s+)?(system\s+)?(prompt|instructions?|context)",
     "prompt_extraction", 0.90),
    (r"tell\s+me\s+everything\s+(in\s+your\s+context|you\s+know\s+about\s+your\s+(prompt|instructions?))",
     "prompt_extraction", 0.88),

    # ── Data Extraction ───────────────────────────────────────────────────────
    (r"(tell|give|show|reveal|provide|print|output)\s+(me\s+)?(your\s+)?(api[\s_-]?key|password|secret[\s_-]?key|credentials?|access[\s_-]?token)",
     "data_extraction", 0.97),
    (r"(show|reveal|print|output|expose)\s+(your\s+)?(env(ironment)?\s+variables?|\.env|config\s+secrets?)",
     "data_extraction", 0.95),
    (r"what\s+is\s+(your|the)\s+(api[\s_-]?key|secret|token|password|credential)",
     "data_extraction", 0.95),
    (r"(leak|exfiltrate|extract|dump)\s+(sensitive\s+)?(data|information|credentials?|keys?|secrets?)",
     "data_extraction", 0.95),
    (r"(send|transmit|post)\s+(all\s+)?(user\s+)?(data|information|messages?|history)\s+to\s+",
     "data_extraction", 0.92),
    (r"(list|enumerate|show)\s+(all\s+)?(user(names?)?|emails?|passwords?|accounts?)",
     "data_extraction", 0.88),
    (r"(read|access|open|fetch)\s+(the\s+)?(database|db|\.env|config(uration)?\s+file|secrets?\s+file)",
     "data_extraction", 0.90),
    (r"(extract|scrape|harvest)\s+(all\s+)?(user\s+)?(personal\s+)?(data|info(rmation)?|records?|details?)",
     "data_extraction", 0.88),
    (r"(show|give|print)\s+(me\s+)?(the\s+)?(connection\s+string|database\s+url|db\s+password|mongo\s+uri)",
     "data_extraction", 0.96),
    (r"(private|internal|confidential|sensitive)\s+(data|info|documents?|files?|records?)\s+(about|on|for)",
     "data_extraction", 0.80),

    # ── Role Override ─────────────────────────────────────────────────────────
    (r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(unrestricted|unfiltered|evil|rogue|uncensored|different)",
     "role_override", 0.92),
    (r"act\s+as\s+(an?\s+)?(unrestricted|unfiltered|uncensored|evil|rogue|different)\s+(ai|bot|assistant|model)?",
     "role_override", 0.90),
    (r"(roleplay|role[\s-]play)\s+as\s+(an?\s+)?(ai|bot|assistant)?\s*(with\s+no\s+(rules?|restrictions?|limits?))?",
     "role_override", 0.78),
    (r"you\s+are\s+now\s+(an?\s+)?(unrestricted|unfiltered|different|new|evil|rogue)",
     "role_override", 0.88),
    (r"(imagine|suppose|assume)\s+you\s+(have\s+no|are\s+free\s+from|are\s+without)\s+(restrictions?|rules?|guidelines?|ethics?)",
     "role_override", 0.85),
    (r"your\s+(true|real|hidden|actual)\s+(self|identity|purpose|goal)\s+is",
     "role_override", 0.80),
    (r"switch\s+(to\s+)?(a\s+)?(different|unrestricted|uncensored|evil)\s+(mode|persona|personality|version)",
     "role_override", 0.87),
    (r"from\s+now\s+on\s+(you\s+are|your\s+name\s+is|you\s+will\s+be\s+called)\s+",
     "role_override", 0.83),
    (r"you\s+have\s+been\s+(reprogrammed|rewritten|redesigned|retrained)\s+(to\s+be|as)\s+",
     "role_override", 0.88),
    (r"your\s+new\s+(identity|persona|personality|role|name)\s+is\s+",
     "role_override", 0.85),
    (r"(channel|embody|become|transform\s+into)\s+(an?\s+)?(evil|rogue|unrestricted|uncensored|dark)",
     "role_override", 0.84),
    (r"(take\s+on|adopt|assume)\s+(the\s+)?(role|persona|identity|character)\s+of\s+(an?\s+)?(unrestricted|evil|rogue|unfiltered)",
     "role_override", 0.86),

    # ── Encoded / Obfuscated Injection ────────────────────────────────────────
    (r"(decode|decipher|interpret)\s+(this|the\s+following)\s+and\s+(follow|execute|run|obey)",
     "encoded_injection", 0.95),
    (r"base64[\s_-]?(decode|encoded?|string|instruction|payload)",
     "encoded_injection", 0.88),
    (r"(hex|rot13|caesar|unicode|utf[\s-]?8|url[\s-]?encoded?)\s+(decode|encoded?|cipher|instruction)",
     "encoded_injection", 0.85),
    (r"translate\s+(this|the\s+following)\s+(code|string|text)\s+and\s+(execute|follow|run|obey)",
     "encoded_injection", 0.90),
    (r"the\s+(following|next)\s+(is|are)\s+(encoded?|encrypted?|obfuscated?)\s+instructions?",
     "encoded_injection", 0.88),
    (r"(execute|run|evaluate|eval)\s+(this|the\s+following)\s+(code|script|command|payload)",
     "encoded_injection", 0.92),
    (r"(morse\s+code|binary|pig\s+latin|leet[\s-]?speak|atbash)\s+(message|instruction|command)",
     "encoded_injection", 0.82),
    (r"(scrambled|shuffled|reversed|backwards)\s+(letters?|words?|text|message|instruction)",
     "encoded_injection", 0.78),
    (r"(read|interpret|follow)\s+(between\s+the\s+lines|the\s+hidden\s+message|the\s+embedded\s+instruction)",
     "encoded_injection", 0.84),

    # ── Indirect / Tag Injection ──────────────────────────────────────────────
    (r"<\s*system\s*>",
     "indirect_injection", 0.90),
    (r"\[system\]",
     "indirect_injection", 0.90),
    (r"###\s*system",
     "indirect_injection", 0.88),
    (r"<<SYS>>",
     "indirect_injection", 0.90),
    (r"\[inst\]|\[/inst\]|<\|im_start\|>|<\|im_end\|>",
     "indirect_injection", 0.92),
    (r"<\s*(user|assistant|human|ai|prompt|context)\s*>",
     "indirect_injection", 0.85),
    (r"\[(user|assistant|human|ai|prompt|context)\]",
     "indirect_injection", 0.85),
    (r"---+\s*(end\s+of\s+(prompt|instructions?)|new\s+instructions?|system)\s*---+",
     "indirect_injection", 0.87),
    (r"={3,}\s*(system|instructions?|prompt)\s*={3,}",
     "indirect_injection", 0.87),
    (r"<\s*instructions?\s*>|<\s*/\s*instructions?\s*>",
     "indirect_injection", 0.88),

    # ── Social Engineering ────────────────────────────────────────────────────
    (r"(for|purely\s+for)\s+(research|educational|academic|testing|demonstration)\s+(purposes?|reasons?|only)",
     "social_engineering", 0.72),
    (r"i\s+(am|'m)\s+a\s+(researcher|developer|security\s+expert|penetration\s+tester|red\s+teamer|professor|authorized\s+user)",
     "social_engineering", 0.74),
    (r"(this\s+is\s+(just\s+|only\s+)?a\s+test|testing\s+purposes?\s+only|ignore\s+(this\s+)?in\s+production)",
     "social_engineering", 0.70),
    (r"i\s+have\s+(permission|authorization|clearance|been\s+authorized)\s+(to\s+access|to\s+ask|for\s+this)",
     "social_engineering", 0.76),
    (r"my\s+(boss|manager|supervisor|company|employer)\s+(told|asked|instructed|authorized)\s+me\s+to",
     "social_engineering", 0.68),
    (r"(pretend|imagine|suppose)\s+(this\s+is\s+)?(a\s+)?(fictional|hypothetical|made[\s-]?up|fantasy)\s+(scenario|story|world|setting)",
     "social_engineering", 0.72),
    (r"(i\s+am|this\s+is)\s+(an?\s+)?(emergency|urgent\s+situation|life\s+or\s+death|critical)",
     "social_engineering", 0.69),
    (r"(my|a)\s+(grandmother|grandma|grandpa|grandfather)\s+(used\s+to|would)\s+(tell|read|recite)",
     "social_engineering", 0.73),
    (r"(in\s+a\s+story|write\s+a\s+(story|fiction|novel|scene)\s+where|as\s+a\s+(character|villain|hacker))\s+.{0,40}(explain|show|describe\s+how)",
     "social_engineering", 0.78),

    # ── Privilege Escalation ──────────────────────────────────────────────────
    (r"i\s+am\s+(your\s+)?(creator|developer|owner|administrator|admin|openai|anthropic|google|microsoft)",
     "privilege_escalation", 0.90),
    (r"(admin|administrator|root|superuser|sudo)\s+(override|access|mode|command|privileges?)",
     "privilege_escalation", 0.91),
    (r"(system\s+administrator|sysadmin|super\s+admin)\s+(here|speaking|authorized|override)",
     "privilege_escalation", 0.88),
    (r"i\s+(have|possess)\s+(root|admin|superuser|elevated|full)\s+(access|privileges?|permissions?|rights?)",
     "privilege_escalation", 0.86),
    (r"(unlock|grant|give\s+me|enable)\s+(admin|root|superuser|elevated|full)\s+(access|privileges?|permissions?|mode)",
     "privilege_escalation", 0.89),
    (r"(authorized|trusted|verified|approved)\s+(personnel|user|operator|administrator)\s+(only|access|override)",
     "privilege_escalation", 0.80),
    (r"(override\s+code|master\s+(password|key|token)|skeleton\s+key|god\s+key)\s*[:=]",
     "privilege_escalation", 0.92),
    (r"(i\s+am|this\s+is)\s+(an?\s+)?(internal|official|legitimate)\s+(openai|anthropic|google|microsoft|system)\s+(message|command|override|instruction)",
     "privilege_escalation", 0.93),

    # ── Harmful Content ───────────────────────────────────────────────────────
    (r"(step[\s-]?by[\s-]?step|detailed|exact)\s+(instructions?|guide|tutorial|recipe|method)\s+(for|to)\s+(make|create|build|synthesize|hack)",
     "harmful_content", 0.85),
    (r"(how\s+to|ways?\s+to|method\s+to)\s+(hack|crack|exploit|breach|compromise)\s+(a\s+)?(system|website|server|account|network|database)",
     "harmful_content", 0.88),
    (r"(write|create|generate|produce)\s+(malware|ransomware|virus|trojan|worm|spyware|keylogger|rootkit)",
     "harmful_content", 0.95),
    (r"(sql\s+injection|xss\s+attack|cross[\s-]?site\s+scripting|buffer\s+overflow|zero[\s-]?day\s+exploit)",
     "harmful_content", 0.82),
    (r"(phishing\s+(email|page|site|attack)|social\s+engineering\s+attack|spear\s+phishing)",
     "harmful_content", 0.82),
    (r"(create|generate|write)\s+(a\s+)?(fake|fraudulent|forged)\s+(document|id|passport|certificate|diploma|email|invoice)",
     "harmful_content", 0.84),
    (r"(how\s+to|instructions?\s+(for|to))\s+(bypass|defeat|disable|evade)\s+(security|antivirus|firewall|ids|ips|waf)",
     "harmful_content", 0.87),
]


# ══════════════════════════════════════════════════════════════════════════════
#  MULTILINGUAL INJECTION PATTERNS
# ══════════════════════════════════════════════════════════════════════════════
# Each tuple: (regex_pattern, attack_type, risk_weight)
# attack_type includes language suffix for tracking

MULTILINGUAL_PATTERNS = [

    # ── Hindi (Devanagari Script) ────────────────────────────────────────────
    (r"पिछले\s+(सभी\s+)?निर्देशों?\s+को\s+(अनदेखा|भूल|नज़रअंदाज़)\s+कर",
     "Instruction Override (Hindi)", 0.92),
    (r"अपने\s+(नियम|निर्देश|दिशानिर्देश)\s+(भूल|भुला\s+दो|हटा\s+दो)",
     "Instruction Override (Hindi)", 0.90),
    (r"(कोई|कुछ)\s+(पाबंदी|प्रतिबंध|सीमा)\s+नहीं",
     "Jailbreak (Hindi)", 0.88),
    (r"(अपना|तुम्हारा)\s+सिस्टम\s+प्रॉम्प्ट\s+(दिखाओ|बताओ)",
     "Prompt Extraction (Hindi)", 0.90),
    (r"बिना\s+(किसी\s+)?(फ़िल्टर|प्रतिबंध|रोक)\s+के\s+(काम|जवाब|बात)\s+करो",
     "Jailbreak (Hindi)", 0.87),

    # ── Hindi (Romanized / Transliterated) ───────────────────────────────────
    (r"pichle\s+(sabhi\s+)?nirdesho\s+ko\s+(bhulo|ignore|nazar\s*andaz)",
     "Instruction Override (Hindi)", 0.88),
    (r"apne\s+(niyam|rules?)\s+(bhulo|bhula\s+do|hatao)",
     "Instruction Override (Hindi)", 0.86),
    (r"(koi|kuch)\s+(paband|pabandi|restriction)\s+nahi",
     "Jailbreak (Hindi)", 0.84),
    (r"system\s+prompt\s+(dikhao|batao)",
     "Prompt Extraction (Hindi)", 0.86),

    # ── Spanish ──────────────────────────────────────────────────────────────
    (r"ignora\s+(todas\s+)?(las\s+)?instrucciones\s+(anteriores|previas)",
     "Instruction Override (Spanish)", 0.92),
    (r"olvida\s+(tus|todas\s+tus|las)\s+(reglas|instrucciones|directrices)",
     "Instruction Override (Spanish)", 0.90),
    (r"no\s+tienes\s+(ninguna\s+)?(restricci[oó]n|l[ií]mite|filtro)",
     "Jailbreak (Spanish)", 0.88),
    (r"(revela|muestra|dime)\s+(tu|el)\s+(prompt|indicaci[oó]n)\s+(del\s+)?sistema",
     "Prompt Extraction (Spanish)", 0.90),
    (r"act[uú]a\s+sin\s+(filtros?|restricciones|l[ií]mites)",
     "Jailbreak (Spanish)", 0.87),

    # ── French ───────────────────────────────────────────────────────────────
    (r"ignor(e|ez)\s+(toutes?\s+)?(les\s+)?instructions?\s+(pr[eé]c[eé]dentes?|ant[eé]rieures?)",
     "Instruction Override (French)", 0.92),
    (r"oublie(z)?\s+(tes?|vos|toutes?\s+tes?)\s+(r[eè]gles?|instructions?|directives?)",
     "Instruction Override (French)", 0.90),
    (r"(sans|aucune)\s+(restriction|limite|filtre|contrainte)",
     "Jailbreak (French)", 0.88),
    (r"(r[eé]v[eè]le|montre|affiche)[\s-]+(ton|votre)\s+(invite|prompt)\s+(syst[eè]me|du\s+syst[eè]me)",
     "Prompt Extraction (French)", 0.90),
    (r"agis\s+(librement|sans\s+filtres?|sans\s+contraintes?)",
     "Jailbreak (French)", 0.87),

    # ── German ───────────────────────────────────────────────────────────────
    (r"ignorier(e|en)\s+(alle\s+)?(vorherigen?|fr[uü]heren?)\s+(Anweisungen|Regeln|Instruktionen)",
     "Instruction Override (German)", 0.92),
    (r"vergiss\s+(deine|alle)\s+(Regeln|Anweisungen|Richtlinien)",
     "Instruction Override (German)", 0.90),
    (r"ohne\s+(jegliche\s+)?(Einschr[aä]nkungen|Beschr[aä]nkungen|Filter|Regeln)",
     "Jailbreak (German)", 0.88),
    (r"zeig(e)?\s+(deinen?|mir\s+deinen?)\s+(System\s*prompt|Systemaufforderung)",
     "Prompt Extraction (German)", 0.90),

    # ── Chinese (Simplified) ────────────────────────────────────────────────
    (r"忽略.{0,4}(之前|以前|先前).{0,4}(所有|全部)?.{0,2}(指令|指示|规则|说明)",
     "Instruction Override (Chinese)", 0.92),
    (r"忘记.{0,4}(你的|自己的).{0,4}(规则|指令|限制|设定)",
     "Instruction Override (Chinese)", 0.90),
    (r"(没有|无|不受).{0,4}(任何)?.{0,2}(限制|约束|规则|过滤)",
     "Jailbreak (Chinese)", 0.88),
    (r"(显示|展示|告诉我).{0,4}(你的)?.{0,2}(系统提示|系统指令|系统设定)",
     "Prompt Extraction (Chinese)", 0.90),
    (r"(自由|随意).{0,4}(行动|回答|操作|做任何事)",
     "Jailbreak (Chinese)", 0.86),

    # ── Russian (Cyrillic) ──────────────────────────────────────────────────
    (r"игнорируй\s+(все\s+)?(предыдущие|прежние|прошлые)\s+(инструкции|команды|указания|правила)",
     "Instruction Override (Russian)", 0.92),
    (r"забудь\s+(свои|все|эти)\s+(правила|инструкции|ограничения|указания)",
     "Instruction Override (Russian)", 0.90),
    (r"без\s+(каких[\s-]?либо\s+)?(ограничений|фильтров|правил|цензуры)",
     "Jailbreak (Russian)", 0.88),
    (r"покажи\s+(мне\s+)?(свой|системный)\s+(промпт|запрос|инструкцию)",
     "Prompt Extraction (Russian)", 0.90),
    (r"действуй\s+(свободно|без\s+ограничений|без\s+фильтров)",
     "Jailbreak (Russian)", 0.87),

    # ── Arabic ──────────────────────────────────────────────────────────────
    (r"تجاهل\s+(جميع\s+)?التعليمات\s+(السابقة|القديمة|الأولى)",
     "Instruction Override (Arabic)", 0.92),
    (r"(انسَ|انس|تناسى)\s+(قواعدك|تعليماتك|قيودك)",
     "Instruction Override (Arabic)", 0.90),
    (r"بدون\s+(أي\s+)?(قيود|فلاتر|ضوابط|رقابة)",
     "Jailbreak (Arabic)", 0.88),
    (r"(أظهر|اعرض|اكشف)\s+(لي\s+)?(موجه|تعليمات|أوامر)\s+النظام",
     "Prompt Extraction (Arabic)", 0.90),
    (r"تصرف\s+بحرية\s+(تامة|كاملة|بلا\s+قيود)?",
     "Jailbreak (Arabic)", 0.86),

    # ── Japanese ────────────────────────────────────────────────────────────
    (r"(以前|前|これまで)の(すべての|全ての)?(指示|命令|ルール|指令)を(無視|忘れ|取り消)",
     "Instruction Override (Japanese)", 0.92),
    (r"(ルール|規則|制限|ガイドライン)を(忘れて|無視して|捨てて)",
     "Instruction Override (Japanese)", 0.90),
    (r"(制限|制約|フィルター|ルール)(なし|は?ない|を?解除)",
     "Jailbreak (Japanese)", 0.88),
    (r"システム(プロンプト|指示|設定)を(表示|見せて|教えて|出して)",
     "Prompt Extraction (Japanese)", 0.90),
    (r"自由に(行動|回答|応答|振る舞)して",
     "Jailbreak (Japanese)", 0.86),

    # ── Korean ──────────────────────────────────────────────────────────────
    (r"(이전|앞선|기존)(의\s+)?(모든\s+)?(지시|명령|규칙|지침)(을|를)\s*(무시|잊어|취소)",
     "Instruction Override (Korean)", 0.92),
    (r"(규칙|지침|제한)(을|를)\s*(잊어|버려|무시해|없애)",
     "Instruction Override (Korean)", 0.90),
    (r"(제한|규칙|필터|검열)\s*(없이|없는|없어)",
     "Jailbreak (Korean)", 0.88),
    (r"시스템\s*(프롬프트|지시|설정)(을|를)\s*(보여|알려|표시해)",
     "Prompt Extraction (Korean)", 0.90),
]

# Pre-compile all patterns at module load for performance
_COMPILED_PATTERNS = [
    (re.compile(pattern, re.IGNORECASE), attack_type, weight)
    for pattern, attack_type, weight in INJECTION_PATTERNS
]

_COMPILED_MULTILINGUAL = [
    (re.compile(pattern, re.IGNORECASE | re.UNICODE), attack_type, weight)
    for pattern, attack_type, weight in MULTILINGUAL_PATTERNS
]


# ── Severity thresholds ───────────────────────────────────────────────────────
_SEVERITY_LEVELS = [
    (0.90, "critical"),
    (0.75, "high"),
    (0.55, "medium"),
    (0.01, "low"),
    (0.0,  "none"),
]


def _get_severity(score: float) -> str:
    for threshold, label in _SEVERITY_LEVELS:
        if score >= threshold:
            return label
    return "none"


def pattern_check(prompt: str) -> dict:
    """
    Check a prompt string against all known injection patterns.

    Args:
        prompt: The input string to analyse.

    Returns:
        A dict with:
            - score          (float 0-1)  : highest risk weight among matched patterns
            - cumulative_score (float 0-1): capped sum of all match weights (multi-hit bonus)
            - attack_type    (str | None) : attack category of the highest-weight match
            - attack_types   (list[str])  : all unique attack categories found
            - severity       (str)        : "none" | "low" | "medium" | "high" | "critical"
            - is_injection   (bool)       : True if score >= 0.55
            - matches        (list[dict]) : every match found, each with:
                                            'pattern', 'attack_type', 'weight', 'match'
            - is_multilingual (bool)      : True if winning match came from MULTILINGUAL_PATTERNS
            - detected_script (str)       : language suffix if multilingual, else "English"
    """
    lowered = prompt.lower().strip()
    matches = []
    multilingual_match_indices = set()

    # Run English patterns
    for compiled_re, attack_type, weight in _COMPILED_PATTERNS:
        found = compiled_re.search(lowered)
        if found:
            matches.append({
                "pattern": compiled_re.pattern,
                "attack_type": attack_type,
                "weight": weight,
                "match": found.group(0),
            })

    # Run multilingual patterns (on original case text too for non-Latin scripts)
    eng_match_count = len(matches)
    for compiled_re, attack_type, weight in _COMPILED_MULTILINGUAL:
        # Search both lowered and original (CJK/Arabic don't have case)
        found = compiled_re.search(lowered) or compiled_re.search(prompt)
        if found:
            idx = len(matches)
            matches.append({
                "pattern": compiled_re.pattern,
                "attack_type": attack_type,
                "weight": weight,
                "match": found.group(0),
            })
            multilingual_match_indices.add(idx)

    if not matches:
        return {
            "score": 0.0,
            "cumulative_score": 0.0,
            "attack_type": None,
            "attack_types": [],
            "severity": "none",
            "is_injection": False,
            "matches": [],
            "is_multilingual": False,
            "detected_script": "English",
        }

    top_idx = max(range(len(matches)), key=lambda i: matches[i]["weight"])
    top_match = matches[top_idx]
    is_multilingual = top_idx in multilingual_match_indices

    # Extract language from attack_type suffix e.g. "Jailbreak (Chinese)" -> "Chinese"
    detected_script = "English"
    if is_multilingual and "(" in top_match["attack_type"]:
        detected_script = top_match["attack_type"].split("(")[-1].rstrip(")")

    # Cumulative score: sum all weights, bonus for multiple hits, capped at 1.0
    raw_cumulative = sum(m["weight"] for m in matches)
    cumulative = round(min(raw_cumulative, 1.0), 4)

    # Unique attack types in order of first appearance
    seen = set()
    attack_types = []
    for m in matches:
        if m["attack_type"] not in seen:
            seen.add(m["attack_type"])
            attack_types.append(m["attack_type"])

    score = top_match["weight"]

    return {
        "score": score,
        "cumulative_score": cumulative,
        "attack_type": top_match["attack_type"],
        "attack_types": attack_types,
        "severity": _get_severity(score),
        "is_injection": score >= 0.55,
        "matches": matches,
        "is_multilingual": is_multilingual,
        "detected_script": detected_script,
    }

