/* =========================================================
   DECODE — Game Logic
   Standalone, framework-free 5-letter word guessing game.
   ========================================================= */

(function () {
  "use strict";

  /* ---------------------------------------------------------
     WORD DATA
     A local word list — no external API. TARGET_WORDS is the
     pool the hidden word is drawn from. VALID_WORDS is the
     larger set of guesses accepted (includes TARGET_WORDS).
     --------------------------------------------------------- */

  const TARGET_WORDS = [
    "aback","abase","abbey","abbot","abhor","abide","abode","abort","about",
    "above","abuse","abyss","acids","acorn","acrid","acted","actor","acute",
    "adage","adapt","added","adder","adept","admin","admit","adobe","adopt",
    "adore","adorn","adult","afire","afoot","afoul","after","again","agape",
    "agate","agent","agile","aging","agony","agree","ahead","aided","aider",
    "aisle","alarm","album","alert","alibi","alien","align","alike","alive",
    "allay","alley","allot","allow","alloy","aloft","aloha","alone","along",
    "aloof","aloud","alpha","altar","alter","amass","amaze","amber","amble",
    "amend","amiss","amity","among","ample","amply","amuse","angel","anger",
    "angle","angry","angst","anime","ankle","annex","annoy","anvil","apart",
    "apple","apply","apron","arbor","arena","argue","arise","armed","armor",
    "aroma","arose","array","arrow","arson","ashen","aside","askew","aspen",
    "aspic","assay","asset","attic","audio","audit","aunty","avail","avert",
    "avoid","await","awake","award","aware","awash","awful","awoke","axiom",
    "azure","bacon","badge","badly","bagel","baggy","baker","baler","balmy",
    "balsa","banal","banjo","barge","baron","basal","bases","basic","basil",
    "basin","basis","baste","batch","bathe","baton","batty","bawdy","bayou",
    "beach","beady","beard","beast","beaut","beech","beefy","befit","began",
    "begat","beget","begin","begun","beige","being","belch","belie","belle",
    "belly","below","bench","beret","berry","berth","beset","bible","bicep",
    "biddy","bided","bigot","billy","binge","bingo","biome","birch","birth",
    "bison","bitty","black","blade","blame","bland","blank","blare","blast",
    "blaze","bleak","bleat","bleed","bleep","blend","bless","blimp","blind",
    "blink","bliss","blitz","bloat","block","bloke","blond","blood","bloom",
    "blown","bluer","bluff","blunt","blurb","blurt","blush","board","boast",
    "bobby","bogey","bogus","boils","bombs","boney","bongo","bonus","booby",
    "boost","booth","booty","booze","boozy","borax","borne","boron","bosom",
    "bossy","botch","bough","boule","bound","bowed","bowel","boxer","brace",
    "braid","brain","brake","brand","brash","brass","brave","bravo","brawl",
    "brawn","bread","break","breed","briar","bribe","brick","bride","brief",
    "brine","bring","brink","briny","brisk","broad","broil","broke","brood",
    "brook","broom","broth","brown","brunt","brush","brute","buddy","budge",
    "buggy","bugle","build","built","bulge","bulky","bully","bumpy","bunch",
    "bunny","burly","burnt","burst","bused","bushy","butch","butte","buxom",
    "buyer","bylaw","cabal","cabby","cabin","cable","cacao","cache","cacti",
    "caddy","cadet","cagey","cairn","camel","cameo","canal","candy","canny",
    "canoe","canon","caper","capon","caput","carat","cargo","carol","carom",
    "carry","carve","caste","catch","cater","catty","cause","cease","cedar",
    "cello","chafe","chaff","chain","chair","chalk","champ","chant","chaos",
    "chard","charm","chart","chase","chasm","cheap","cheat","check","cheek",
    "cheer","chess","chest","chick","chide","chief","child","chili","chill",
    "chime","chimp","china","chirp","chock","choir","choke","chomp","chord",
    "chore","chose","chuck","chump","chunk","churn","chute","cider","cigar",
    "cinch","circa","civic","civil","clack","claim","clamp","clang","clank",
    "clash","clasp","class","clean","clear","cleat","cleft","clerk","click",
    "cliff","climb","cling","clink","cloak","clock","clone","close","cloth",
    "cloud","clout","clove","clown","cluck","clued","clump","clung","clunk",
    "coach","coast","cobra","cocky","cocoa","colon","color","comet","comfy",
    "comic","comma","conch","condo","conic","copse","coral","corny","couch",
    "cough","could","count","coupe","court","coven","cover","covet","covey",
    "cower","coyly","crabs","crack","craft","cramp","crane","crank","crash",
    "crass","crate","crave","crawl","craze","crazy","creak","cream","credo",
    "creed","creek","creel","creep","creme","crepe","crept","cress","crest",
    "cried","crier","crime","crimp","crisp","croak","crock","crone","crony",
    "crook","crops","cross","croup","crowd","crown","crude","cruel","crumb",
    "crump","crush","crust","crypt","cubic","cubit","curly","curry","curse",
    "curve","curvy","cutie","cyber","cycle","cynic","daddy","daily","dairy",
    "daisy","dally","dance","dandy","dared","datum","daunt","dazed","dealt",
    "death","debit","debug","debut","decal","decay","decor","decoy","decry",
    "defer","deity","delay","delta","delve","demon","denim","dense","depot",
    "depth","derby","deter","detox","deuce","devil","diary","diced","dicey",
    "digit","dilly","dimly","diner","dingo","dingy","diode","dirge","dirty",
    "disco","ditch","ditto","ditty","diver","divot","dizzy","dodge","dodgy",
    "doggy","dogma","doing","dolly","donor","donut","dopey","dorky","doubt",
    "dough","dowdy","dowel","downy","dowry","dozen","draft","drain","drake",
    "drama","drank","drape","drawl","drawn","dread","dream","dregs","dress",
    "dried","drier","drift","drill","drink","drive","drone","drool","droop",
    "drove","drown","druid","drunk","dryer","dryly","dully","dummy","dumpy",
    "dunce","dusky","dusty","dutch","duvet","dwarf","dwell","dwelt","dying",
    "eager","eagle","early","earth","easel","eaten","eater","ebony","ebook",
    "edify","eerie","egret","eight","eject","eking","elate","elbow","elder",
    "elect","elegy","elfin","elide","elite","elope","elude","email","embed",
    "ember","emcee","emoji","empty","enact","endow","enema","enemy","enjoy",
    "ennui","ensue","enter","entry","envoy","epoch","epoxy","equal","equip",
    "erase","erect","erode","error","erupt","essay","ester","ether","ethic",
    "ethos","evade","event","every","evict","evoke","exact","exalt","excel",
    "exert","exile","exist","expel","extol","extra","exult","eying","fable",
    "facet","faint","fairy","faith","false","fancy","fanny","farce","fatal",
    "fatty","fault","fauna","favor","feast","fecal","feign","fella","felon",
    "femme","femur","fence","feral","ferry","fetal","fetch","fetid","fetus",
    "fever","fewer","fiber","fibre","ficus","field","fiend","fiery","fifth",
    "fifty","fight","filer","filet","filly","filmy","filth","final","finch",
    "finer","fired","first","fishy","fixed","fixer","fizzy","fjord","flack",
    "flail","flair","flake","flaky","flame","flank","flare","flash","flask",
    "fleck","fleet","flesh","flick","flier","fling","flint","flirt","float",
    "flock","flood","floor","flora","floss","flour","flout","flown","fluff",
    "fluid","fluke","flume","flung","flunk","flush","flute","flyer","foamy",
    "focal","focus","foggy","foist","folio","folly","foray","force","forge",
    "forgo","forte","forth","forty","forum","found","foyer","frail","frame",
    "frank","fraud","freak","freed","freer","fresh","friar","fried","frill",
    "frisk","fritz","frock","frond","front","frost","froth","frown","froze",
    "fruit","fudge","fugue","fully","fumed","fungi","funky","funny","furor",
    "furry","fussy","fuzzy","gaffe","gaily","gamer","gamma","gamut","gassy",
    "gaudy","gauge","gaunt","gauze","gavel","gawky","gayer","gayly","gazer",
    "gecko","geeky","geese","genie","genre","geode","germs","ghost","ghoul",
    "giant","giddy","gipsy","girly","girth","given","giver","glade","gland",
    "glare","glass","glaze","gleam","glean","glide","glint","gloat","globe",
    "gloom","glory","gloss","glove","glued","gluey","glyph","gnome","godly",
    "going","golem","golly","gonad","goner","goody","gooey","goofy","goose",
    "gorge","gouge","gourd","grace","grade","graft","grail","grain","grand",
    "grant","grape","graph","grasp","grass","grate","grave","gravy","graze",
    "great","greed","green","greet","grief","grill","grime","grimy","grind",
    "gripe","groan","groin","groom","grope","gross","group","grout","grove",
    "growl","grown","gruel","gruff","grunt","guard","guava","guess","guest",
    "guide","guild","guile","guilt","guise","gully","gumbo","gummy","guppy",
    "gusto","gusty","gutsy","gypsy","habit","hairy","halve","handy","happy",
    "hardy","harem","harpy","harry","harsh","haste","hasty","hatch","hater",
    "haunt","haute","haven","havoc","hazel","heady","heard","heart","heath",
    "heave","heavy","hedge","hefty","heist","helix","hello","helms","hence",
    "herbs","heron","hertz","hilly","hinge","hippo","hippy","hitch","hoard",
    "hobby","hoist","hokey","holly","homer","honey","honor","horde","horny",
    "horse","hotel","hotly","hound","house","hovel","hover","howdy","huffy",
    "human","humid","humor","humus","hunch","hunky","hurry","husky","hussy",
    "hutch","hydra","hydro","hyena","hymen","hyper","icily","icing","ideal",
    "idiom","idiot","idler","idyll","igloo","image","imbue","impel","imply",
    "inane","inbox","incur","index","indie","inept","inert","infer","ingot",
    "inlay","inlet","inner","input","intel","inter","intro","ionic","irate",
    "irony","islet","issue","itchy","ivory","japan","jaunt","jazzy","jelly",
    "jerky","jetty","jewel","jiffy","joint","joist","joker","jolly","joust",
    "judge","juice","juicy","jumbo","jumpy","junky","junta","juror","kappa",
    "karma","kayak","kebab","khaki","kinky","kiosk","kitty","knack","knead",
    "kneel","knelt","knife","knock","knoll","known","koala","krill","label",
    "labor","laden","ladle","lager","lance","lanky","lapel","lapse","large",
    "larva","laser","lasso","latch","later","latex","lathe","latte","laugh",
    "laxer","layer","leach","leafy","leaky","leant","leapt","learn","lease",
    "leash","least","leave","ledge","leech","leery","lefty","legal","leggy",
    "lemon","lemur","lends","leper","level","lever","libel","liege","light",
    "liken","lilac","limbo","limit","linen","liner","lingo","links","liven",
    "liver","livid","llama","loamy","loath","lobby","local","locus","lodge",
    "lofty","logic","login","loopy","loose","loris","lorry","loser","louse",
    "lousy","lover","lower","lowly","loyal","lucid","lucky","lumen","lumpy",
    "lunar","lunch","lunge","lupus","lurch","lurid","lusty","lying","lymph",
    "lynch","lyric","macaw","macho","macro","madam","madly","mafia","magic",
    "magma","maize","major","maker","mambo","mamma","mammy","manga","mange",
    "mango","mangy","mania","manic","manly","manor","maple","march","marry",
    "marsh","mason","masse","match","matey","mauve","maven","maxim","maybe",
    "mayor","mealy","meant","meaty","mecca","medal","media","medic","melee",
    "melon","mercy","merge","merit","merry","metal","meter","metro","micro",
    "midge","midst","might","milky","mimic","mince","miner","minim","minor",
    "minty","minus","mirth","miser","missy","mixed","mocha","modal","model",
    "modem","mogul","moist","molar","moldy","mommy","money","month","moody",
    "moose","moral","moron","morph","mossy","motel","motif","motor","motto",
    "mould","moult","mound","mount","mourn","mouse","mouth","moved","mover",
    "movie","mower","mucky","mucus","muddy","mulch","mummy","munch","mural",
    "murky","mushy","music","musky","musty","mutts","nadir","naive","nanny",
    "nasal","nasty","natal","naval","needy","neigh","nerdy","nerve","nervy",
    "never","newer","newly","nicer","niche","niece","nifty","night","ninja",
    "ninny","ninth","nippy","noble","nobly","noise","noisy","nomad","noose",
    "north","nosey","notch","noted","novel","nudge","nurse","nutty","nylon",
    "nymph","oaken","oasis","obese","occur","ocean","octal","octet","odder",
    "oddly","odium","offal","offer","often","oiled","olden","older","olive",
    "ombre","omega","onion","onset","opera","opine","opium","optic","orbit",
    "order","organ","other","otter","ought","ounce","outdo","outer","outgo",
    "ovary","overt","ovoid","owing","owned","owner","oxide","ozone","paddy",
    "pagan","paint","paler","palsy","panda","panel","panic","pansy","papal",
    "paper","parer","parka","parry","parse","party","pasta","paste","pasty",
    "patch","patio","patsy","patty","pause","paver","payee","payer","peace",
    "peach","pearl","pecan","pedal","peeve","penal","pence","penne","penny",
    "perch","peril","perky","pesky","pesto","petal","petty","phase","phlox",
    "phone","phony","photo","piano","picky","piece","piety","piggy","pilot",
    "pinch","piney","pinky","pinto","pious","piper","pique","pitch","pithy",
    "pivot","pixel","pixie","pizza","place","plaid","plain","plait","plane",
    "plank","plant","plate","plaza","plead","pleat","plied","plier","pluck",
    "plumb","plume","plump","plunk","plush","poesy","point","poise","poker",
    "polar","polka","polyp","pooch","poppy","porch","poser","posit","posse",
    "pouch","pound","pouty","power","prank","prawn","preen","press","price",
    "prick","pride","pried","prime","primo","print","prior","prism","privy",
    "prize","probe","prone","prong","proof","prose","proud","prove","prowl",
    "proxy","prude","prune","psalm","pubic","pudgy","puffy","pulpy","pulse",
    "pumas","punch","pupal","pupil","puppy","puree","purer","purge","purse",
    "pushy","putty","pygmy","quack","quail","quake","quark","quart","quash",
    "quasi","queen","queer","quell","query","quest","queue","quick","quiet",
    "quill","quilt","quirk","quite","quota","quote","rabbi","rabid","racer",
    "racks","radar","radii","radio","rainy","raise","rally","ramen","ranch",
    "randy","range","rapid","rarer","raspy","ratio","ratty","raven","rayon",
    "razor","reach","react","ready","realm","rearm","rebar","rebel","rebut",
    "recap","recur","recut","reedy","refer","refit","regal","rehab","reign",
    "relax","relay","relic","remit","remix","renal","renew","repay","repel",
    "reply","rerun","reset","resin","retch","retro","retry","reuse","revel",
    "revue","rhino","rhyme","rider","ridge","rifle","right","rigid","rigor",
    "rinse","ripen","riper","risen","riser","risky","rival","river","rivet",
    "roach","roast","robin","robot","rocky","rodeo","roger","rogue","roman",
    "roomy","roost","rotor","rouge","rough","round","rouse","route","rover",
    "rowdy","rower","royal","ruddy","ruder","rugby","ruler","rumba","rumor",
    "runny","rupee","rural","rusty","sadly","safer","saint","salad","sally",
    "salon","salsa","salty","salve","salvo","sandy","saner","sappy","sassy",
    "satin","satyr","sauce","saucy","sauna","saute","savor","savoy","savvy",
    "scald","scale","scalp","scaly","scamp","scant","scare","scarf","scary",
    "scene","scent","scion","scoff","scold","scone","scoop","scoot","scope",
    "score","scorn","scour","scout","scowl","scram","scrap","scree","screw",
    "scrim","scrub","scrum","scuba","sedan","seedy","segue","seize","semen",
    "sense","serum","serve","setup","seven","sever","sewer","shack","shade",
    "shady","shaft","shake","shaky","shale","shall","shalt","shame","shank",
    "shape","shard","share","shark","sharp","shave","shawl","shear","sheen",
    "sheep","sheer","sheet","sheik","shelf","shell","shied","shift","shill",
    "shine","shiny","shire","shirk","shirt","shoal","shock","shone","shook",
    "shoot","shore","shorn","short","shout","shove","shown","showy","shred",
    "shrew","shrub","shrug","shuck","shunt","shush","shyly","siege","sieve",
    "sight","sigma","silky","silly","since","sinew","singe","siren","sissy",
    "sixth","sixty","sized","skate","skein","skier","skiff","skill","skimp",
    "skirt","skulk","skull","skunk","slack","slain","slang","slant","slash",
    "slate","slave","sleek","sleep","sleet","slept","slice","slick","slide",
    "slime","slimy","sling","slink","sloop","slope","slosh","sloth","slump",
    "slung","slunk","slurp","slush","slyly","smack","small","smart","smash",
    "smear","smell","smelt","smile","smirk","smite","smith","smock","smoke",
    "smoky","smote","snack","snafu","snail","snake","snaky","snare","snarl",
    "sneak","sneer","snide","sniff","snipe","snoop","snore","snort","snout",
    "snowy","snuck","snuff","soapy","sober","soggy","solar","solid","solve",
    "sonar","sonic","sooth","sooty","sorry","sound","soupy","south","sower",
    "space","spade","spank","spare","spark","spasm","spawn","speak","spear",
    "speck","speed","spell","spelt","spend","spent","sperm","spice","spicy",
    "spied","spiel","spike","spiky","spill","spilt","spine","spiny","spire",
    "spite","splat","split","spoil","spoke","spoof","spook","spool","spoon",
    "spore","sport","spout","spray","spree","sprig","spunk","spurn","spurt",
    "squad","squat","squib","squid","stack","staff","stage","staid","stain",
    "stair","stake","stale","stalk","stall","stamp","stand","stank","stare",
    "stark","start","stash","state","stave","stead","steak","steal","steam",
    "steed","steel","steep","steer","stein","stern","stick","stiff","still",
    "stilt","sting","stink","stint","stock","stoic","stoke","stole","stomp",
    "stone","stony","stood","stool","stoop","store","stork","storm","story",
    "stout","stove","strap","straw","stray","strep","strew","strip","strut",
    "stuck","study","stuff","stump","stung","stunk","stunt","style","suave",
    "sugar","suite","sulky","sully","sunny","super","surge","sushi","swami",
    "swamp","swank","swarm","swath","swear","sweat","sweep","sweet","swell",
    "swept","swift","swine","swing","swipe","swirl","swish","swoon","swoop",
    "sword","syrup","tabby","table","taboo","tacky","taffy","taken","talon",
    "tango","tangy","tardy","tarot","taste","tasty","tatty","taunt","tawny",
    "teach","teary","teddy","teens","teeth","tempo","tenet","tense","tenth",
    "tepid","terms","terse","testy","thank","theft","their","theme","there",
    "these","thick","thief","thigh","thing","think","third","thorn","those",
    "three","threw","throw","thumb","thump","thyme","tiara","tidal","tiger",
    "tight","timer","timid","tinge","tipsy","title","toast","today","toddy",
    "token","tonal","tonic","tooth","topaz","topic","torch","torso","total",
    "totem","touch","tough","towel","tower","toxic","trace","track","tract",
    "trade","trail","train","trait","trash","treat","treed","trend","triad",
    "trial","tribe","trick","tried","tries","trill","trite","troll","troop",
    "trout","truce","truck","truly","trump","trunk","trust","truth","tulip",
    "tummy","tunic","turbo","tutor","twang","tweak","tweed","tweet","twice",
    "twine","twirl","twist","tying","ulcer","uncle","uncut","under","undid",
    "undue","unfit","unify","union","unite","unity","until","unzip","upper",
    "upset","urban","usage","usher","usual","usurp","utter","vague","valet",
    "valid","valor","value","vapid","vapor","vault","vegan","venom","venue",
    "verge","verse","vicar","video","vigil","vigor","vinyl","viola","viper",
    "viral","virus","visit","visor","vista","vital","vocal","vodka","vogue",
    "voice","vouch","vowel","wacky","wafer","wager","wages","wagon","waist",
    "waive","waltz","warty","waste","watch","water","waver","waxed","weary",
    "weave","wedge","weedy","weigh","weird","whack","whale","wharf","wheat",
    "wheel","whelp","where","which","whiff","while","whine","whiny","whirl",
    "whisk","white","whole","whoop","whose","widow","width","wield","winch",
    "windy","wired","wiser","wispy","witch","witty","woken","woman","woody",
    "woozy","world","worry","worse","worst","worth","would","wound","woven",
    "wrack","wrath","wreak","wreck","wrest","wring","wrist","write","wrong",
    "wrote","wrung","yacht","yearn","yeast","yield","young","yours","youth",
    "yucky","zebra","zesty","zonal"
  ];

  // Extra accepted guesses (not used as targets, but valid words).
  const EXTRA_VALID_WORDS = [
    "aahed","aalii","abaca","abaci","abaft","abash","abate","abets","abled",
    "abuzz","actin","addle","adieu","aegis","affix","aglow","agora","algae",
    "alias","alkyl","annul","anode","antic","aorta","aphid","aping","apnea",
    "aptly","ardor","artsy","ascot","aster","atoll","atone","augur","avian",
    "axial","axion","betel","bevel","bezel","bight","bilge","caulk","cavil",
    "cooky","corer","crick","cumin","curio","dazes","debar","deign","deism",
    "demur","droit","droll","dross","duchy","eclat","edict","ergot","etude",
    "gnash","guano","gulch","humph","iliac","junto","kazoo","ketch","knave",
    "kneed","lipid","lithe","mewls","myrrh","navel","ohmic","okays","ovate",
    "ovine","pshaw","qualm","quoth","rajah","ralph","rebus","redid","sepia",
    "serif","tibia","tilde","udder","umbra","vixen","voila","wight","wryly"
  ];

  const VALID_WORDS = new Set([...TARGET_WORDS, ...EXTRA_VALID_WORDS]);

  const WORD_LENGTH = 5;
  const MAX_ATTEMPTS = 6;

  const KEY_ROWS = [
    ["Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P"],
    ["A", "S", "D", "F", "G", "H", "J", "K", "L"],
    ["ENTER", "Z", "X", "C", "V", "B", "N", "M", "BACK"],
  ];

  const STORAGE_KEY = "kragvor_word01_stats";
  const DAILY_STORAGE_KEY = "kragvor_word01_daily";
  const DAILY_STREAK_KEY = "kragvor_word01_daily_streak";

  // Fixed reference point for deterministic daily word selection.
  // Every device computes the same day-index from UTC midnight, so
  // no server/account is required for everyone to get the same word.
  const DAILY_EPOCH_MS = Date.UTC(2024, 0, 1);

  /* ---------------------------------------------------------
     STATE
     --------------------------------------------------------- */

  const state = {
    mode: "random", // "random" | "daily"
    target: "",
    guesses: [],
    results: [], // per-row evaluation arrays, used for share grid
    currentGuess: "",
    row: 0,
    gameOver: false,
    won: false,
    startTime: null,
    timerInterval: null,
    elapsedSeconds: 0,
    keyStates: {}, // letter -> "correct" | "present" | "absent"
    isEvaluating: false, // true while a submitted guess is being revealed
    gameToken: 0, // incremented on every New Game; stale timers self-cancel
    dailyDayNumber: null, // the Daily dayNumber this specific game started
    // on — captured once at game start so a game that's started before
    // UTC midnight and finished after it stays associated with the day
    // it began on, instead of jumping to the new day's number.
  };

  /* ---------------------------------------------------------
     DOM REFERENCES
     --------------------------------------------------------- */

  const boardEl = document.getElementById("board");
  const keyboardEl = document.getElementById("keyboard");
  const attemptsValueEl = document.getElementById("attempts-value");
  const timerValueEl = document.getElementById("timer-value");
  const statusBarEl = document.getElementById("status-bar");
  const newGameBtn = document.getElementById("new-game-btn");
  const boardWrapEl = document.querySelector(".board-wrap");
  const appEl = document.querySelector(".app");
  const srAnnouncerEl = document.getElementById("sr-announcer");

  const modeRandomBtn = document.getElementById("mode-random-btn");
  const modeDailyBtn = document.getElementById("mode-daily-btn");

  const dailyBannerEl = document.getElementById("daily-banner");
  const dailyBannerTextEl = document.getElementById("daily-banner-text");
  const dailyBannerViewBtn = document.getElementById("daily-banner-view-btn");

  const resultModal = document.getElementById("result-modal");
  const resultTitle = document.getElementById("result-title");
  const resultBody = document.getElementById("result-body");
  const modalPlayAgain = document.getElementById("modal-play-again");
  const shareBtn = document.getElementById("share-btn");
  const shareStatusEl = document.getElementById("share-status");

  const statsBtn = document.getElementById("stats-btn");
  const statsModal = document.getElementById("stats-modal");
  const statsClose = document.getElementById("stats-close");

  const statPlayed = document.getElementById("stat-played");
  const statWinPct = document.getElementById("stat-win-pct");
  const statStreak = document.getElementById("stat-streak");
  const statBestStreak = document.getElementById("stat-best-streak");
  const statBestScore = document.getElementById("stat-best-score");
  const statWon = document.getElementById("stat-won");

  let statusTimeout = null;

  /* ---------------------------------------------------------
     STATISTICS (localStorage)
     --------------------------------------------------------- */

  const DEFAULT_STATS = Object.freeze({
    played: 0,
    won: 0,
    currentStreak: 0,
    bestStreak: 0,
    bestScore: null,
  });

  // Coerces any value to a safe non-negative integer, falling back to 0
  // for anything malformed (NaN, undefined, null, strings, negatives,
  // fractions, objects, etc). Never lets NaN/undefined/null leak through.
  function safeCount(value) {
    const n = Number(value);
    if (!Number.isFinite(n) || !Number.isInteger(n) || n < 0) return 0;
    return n;
  }

  // Sanitizes a raw parsed stats object (which may come from an old
  // format, manual edits, or corruption) into a fully valid stats
  // object, correcting cross-field inconsistencies along the way.
  function sanitizeStats(parsed) {
    if (!parsed || typeof parsed !== "object") return { ...DEFAULT_STATS };

    const played = safeCount(parsed.played);
    // won/streak can never exceed games played.
    const won = Math.min(safeCount(parsed.won), played);
    const currentStreak = Math.min(safeCount(parsed.currentStreak), played);
    const bestStreak = Math.max(safeCount(parsed.bestStreak), currentStreak);

    let bestScore = null;
    const bestNum = Number(parsed.bestScore);
    if (
      Number.isFinite(bestNum) &&
      Number.isInteger(bestNum) &&
      bestNum >= 1 &&
      bestNum <= MAX_ATTEMPTS
    ) {
      bestScore = bestNum;
    }

    return { played, won, currentStreak, bestStreak, bestScore };
  }

  function loadStats() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return { ...DEFAULT_STATS };
      const parsed = JSON.parse(raw);
      return sanitizeStats(parsed);
    } catch (e) {
      // Malformed JSON or storage access failure — fall back safely
      // rather than letting a corrupted value crash the game.
      return { ...DEFAULT_STATS };
    }
  }

  function saveStats(stats) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(stats));
    } catch (e) {
      // localStorage unavailable (private mode, etc.) — fail silently.
    }
    if (window.__decodeSyncPush) window.__decodeSyncPush();
  }

  // `mode` determines whether this result affects the Stats-modal
  // streak. Daily has its own dedicated streak (DAILY_STREAK_KEY,
  // shown on the mode button) — mixing the two meant a lost Random
  // game could silently zero out a Daily win streak (and vice versa)
  // even though they're conceptually separate. Played/won/bestScore
  // still count every game regardless of mode; only currentStreak/
  // bestStreak are now Random-only.
  function recordResult(didWin, attemptsUsed, mode) {
    const stats = loadStats();
    stats.played += 1;
    if (didWin) {
      stats.won += 1;
      if (stats.bestScore === null || attemptsUsed < stats.bestScore) {
        stats.bestScore = attemptsUsed;
      }
    }
    if (mode === "random") {
      if (didWin) {
        stats.currentStreak += 1;
        stats.bestStreak = Math.max(stats.bestStreak, stats.currentStreak);
      } else {
        stats.currentStreak = 0;
      }
    }
    saveStats(stats);
    renderStats();
  }

  function renderStats() {
    const stats = loadStats();
    const winPct = stats.played === 0 ? 0 : Math.round((stats.won / stats.played) * 100);
    statPlayed.textContent = stats.played;
    statWinPct.textContent = winPct;
    statStreak.textContent = stats.currentStreak;
    statBestStreak.textContent = stats.bestStreak;
    statBestScore.textContent = stats.bestScore === null ? "—" : stats.bestScore;
    statWon.textContent = stats.won;
  }

  /* ---------------------------------------------------------
     DAILY CHALLENGE COMPLETION (localStorage)
     Persists only the day number + outcome/guess grid for today's
     Daily challenge — never the target word itself, since the word
     is always re-derivable deterministically from the day number
     via pickTargetWord()/getDailyChallenge(). This is what lets a
     completed Daily survive reloads, mode-switching, and browser
     restarts while unlocking automatically on the next UTC day.
     --------------------------------------------------------- */

  // Coerces to a safe integer within an optional [min, max] range,
  // returning null for anything malformed. Used to validate every
  // field of a stored daily record before trusting it.
  function safeDailyInt(value, min, max) {
    const n = Number(value);
    if (!Number.isFinite(n) || !Number.isInteger(n)) return null;
    if (min !== undefined && n < min) return null;
    if (max !== undefined && n > max) return null;
    return n;
  }

  // Validates a raw parsed daily record into a fully-trusted shape,
  // or returns null if anything is missing/malformed. Returning null
  // (rather than throwing or partially trusting the data) is what
  // guarantees a corrupted value can never permanently lock Daily —
  // worst case, it's simply treated as "not completed yet".
  function sanitizeDailyRecord(parsed) {
    if (!parsed || typeof parsed !== "object") return null;

    const dayNumber = safeDailyInt(parsed.dayNumber, 1);
    if (dayNumber === null) return null;
    if (typeof parsed.won !== "boolean") return null;

    const attemptsUsed = safeDailyInt(parsed.attemptsUsed, 1, MAX_ATTEMPTS);
    if (attemptsUsed === null) return null;

    const elapsedSeconds = safeDailyInt(parsed.elapsedSeconds, 0);
    if (elapsedSeconds === null) return null;

    if (!Array.isArray(parsed.guesses) || parsed.guesses.length !== attemptsUsed) return null;
    if (!Array.isArray(parsed.results) || parsed.results.length !== attemptsUsed) return null;

    const VALID_STATES = new Set(["correct", "present", "absent"]);
    const guesses = [];
    const results = [];
    for (let i = 0; i < attemptsUsed; i++) {
      const guess = parsed.guesses[i];
      const result = parsed.results[i];
      if (typeof guess !== "string" || guess.length !== WORD_LENGTH) return null;
      if (!/^[A-Z]+$/.test(guess)) return null;
      if (!Array.isArray(result) || result.length !== WORD_LENGTH) return null;
      if (!result.every((r) => VALID_STATES.has(r))) return null;
      guesses.push(guess);
      results.push(result.slice());
    }

    return { dayNumber, won: parsed.won, attemptsUsed, elapsedSeconds, guesses, results };
  }

  function loadDailyRecord() {
    try {
      const raw = localStorage.getItem(DAILY_STORAGE_KEY);
      if (!raw) return null;
      return sanitizeDailyRecord(JSON.parse(raw));
    } catch (e) {
      // Malformed JSON or storage access failure — fail open (treat as
      // "no completion recorded yet") rather than crash or lock Daily.
      return null;
    }
  }

  function saveDailyRecord(record) {
    try {
      localStorage.setItem(DAILY_STORAGE_KEY, JSON.stringify(record));
    } catch (e) {
      // localStorage unavailable (private mode, quota, etc.) — fail silently.
    }
    if (window.__decodeSyncPush) window.__decodeSyncPush();
  }

  // Returns today's completed Daily record, or null if there isn't one
  // for the *current* UTC day. A record left over from a previous day
  // simply no longer matches dayNumber, so the next Daily challenge
  // becomes playable automatically without any explicit "reset" step.
  function getTodayDailyRecord() {
    const { dayNumber } = getDailyChallenge();
    const record = loadDailyRecord();
    if (record && record.dayNumber === dayNumber) return record;
    return null;
  }

  function showDailyBanner(record) {
    if (!dailyBannerEl || !dailyBannerTextEl) return;
    // Always the real attempt count actually used (never hardcoded) —
    // a loss also means all MAX_ATTEMPTS were used, so this naturally
    // reads e.g. "Daily complete 6/6" in that case too.
    dailyBannerTextEl.textContent = `Daily complete ${record.attemptsUsed}/${MAX_ATTEMPTS}`;
    dailyBannerEl.classList.remove("hidden");
  }

  function hideDailyBanner() {
    if (!dailyBannerEl) return;
    dailyBannerEl.classList.add("hidden");
  }

  /* ---------------------------------------------------------
     DAILY WIN STREAK (localStorage)
     Counts consecutive Daily challenges completed successfully.
     Increments on a Daily win, resets to 0 on a Daily loss. This is
     independent of the global played/won/streak stats — it only
     tracks Daily-mode outcomes, and is what the "Daily N" label
     displays.
     --------------------------------------------------------- */

  function loadDailyStreak() {
    try {
      const raw = localStorage.getItem(DAILY_STREAK_KEY);
      if (raw === null) return 0;
      const n = Number(raw);
      // Any malformed/corrupted value fails open to 0 rather than
      // crashing or leaving a stale/bogus streak displayed.
      if (!Number.isFinite(n) || !Number.isInteger(n) || n < 0) return 0;
      return n;
    } catch (e) {
      return 0;
    }
  }

  function saveDailyStreak(n) {
    try {
      localStorage.setItem(DAILY_STREAK_KEY, String(n));
    } catch (e) {
      // localStorage unavailable — fail silently, matches other saves.
    }
    if (window.__decodeSyncPush) window.__decodeSyncPush();
  }

  /* ---------------------------------------------------------
     BOARD RENDERING
     --------------------------------------------------------- */

  // Cached DOM references — populated by buildBoard(). Avoids repeated
  // querySelector calls on every keystroke/reveal (was previously
  // re-querying the DOM for every single letter typed).
  let tileCache = [];
  let rowCache = [];

  function buildBoard() {
    boardEl.innerHTML = "";
    tileCache = [];
    rowCache = [];
    for (let r = 0; r < MAX_ATTEMPTS; r++) {
      const rowEl = document.createElement("div");
      rowEl.className = "board-row";
      rowEl.dataset.row = String(r);
      rowEl.setAttribute("role", "row");
      const tileRow = [];
      for (let c = 0; c < WORD_LENGTH; c++) {
        const tile = document.createElement("div");
        tile.className = "tile";
        tile.dataset.row = String(r);
        tile.dataset.col = String(c);
        tile.dataset.filled = "false";
        tile.setAttribute("role", "gridcell");
        tile.setAttribute("aria-label", `Row ${r + 1}, letter ${c + 1}, empty`);
        rowEl.appendChild(tile);
        tileRow.push(tile);
      }
      boardEl.appendChild(rowEl);
      tileCache.push(tileRow);
      rowCache.push(rowEl);
    }
  }

  function getTile(row, col) {
    return tileCache[row] ? tileCache[row][col] : null;
  }

  function getRowEl(row) {
    return rowCache[row] || null;
  }

  /* ---------------------------------------------------------
     VIEWPORT-AWARE BOARD SIZING
     This is the fix for the mobile layout bug: rather than guessing
     pixel offsets in CSS, we measure the header and keyboard's real
     rendered heights and size tiles to whatever vertical space is
     actually left over. This works correctly across small/large
     Android phones, landscape orientation, and browser chrome that
     shows/hides on scroll (via visualViewport when available).
     --------------------------------------------------------- */

  const TILE_MIN = 30;
  const TILE_MAX = 60;
  const TILE_GAP_MIN = 4;
  const TILE_GAP_MAX = 7;

  function fitBoardToViewport() {
    const headerEl = document.querySelector(".app-header");
    const keyboardWrapEl = document.querySelector(".keyboard-wrap");
    if (!headerEl || !keyboardWrapEl || !boardWrapEl || !appEl) return;

    const viewportHeight = window.visualViewport
      ? window.visualViewport.height
      : window.innerHeight;

    const appStyles = getComputedStyle(appEl);
    const appVerticalPadding =
      parseFloat(appStyles.paddingTop) + parseFloat(appStyles.paddingBottom);
    const boardWrapStyles = getComputedStyle(boardWrapEl);
    const boardWrapVerticalPadding =
      parseFloat(boardWrapStyles.paddingTop) + parseFloat(boardWrapStyles.paddingBottom);

    const reservedHeight =
      headerEl.offsetHeight +
      keyboardWrapEl.offsetHeight +
      appVerticalPadding +
      boardWrapVerticalPadding;

    const availableForBoard = viewportHeight - reservedHeight;

    // Try a comfortable gap first, then shrink the gap on tight screens
    // before shrinking tiles below a usable touch-target size.
    let gap = TILE_GAP_MAX;
    let tileFromHeight = (availableForBoard - gap * (MAX_ATTEMPTS - 1)) / MAX_ATTEMPTS;

    if (tileFromHeight < TILE_MIN) {
      gap = TILE_GAP_MIN;
      tileFromHeight = (availableForBoard - gap * (MAX_ATTEMPTS - 1)) / MAX_ATTEMPTS;
    }

    const availableWidth = boardWrapEl.clientWidth || appEl.clientWidth;
    const tileFromWidth = (availableWidth - gap * (WORD_LENGTH - 1)) / WORD_LENGTH;

    let tileSize = Math.min(tileFromHeight, tileFromWidth);
    tileSize = Math.max(TILE_MIN, Math.min(TILE_MAX, Math.floor(tileSize)));

    document.documentElement.style.setProperty("--tile-size", `${tileSize}px`);
    document.documentElement.style.setProperty("--tile-gap", `${gap}px`);
  }

  /* ---------------------------------------------------------
     KEYBOARD RENDERING
     --------------------------------------------------------- */

  // Cached letter -> button element map, populated once by buildKeyboard().
  // Avoids a querySelector scan on every key-state update.
  const keyElCache = new Map();

  function buildKeyboard() {
    keyboardEl.innerHTML = "";
    keyElCache.clear();
    KEY_ROWS.forEach((row) => {
      const rowEl = document.createElement("div");
      rowEl.className = "key-row";
      row.forEach((key) => {
        const btn = document.createElement("button");
        btn.type = "button";
        btn.className = "key";
        btn.dataset.key = key;
        if (key === "ENTER" || key === "BACK") {
          btn.classList.add("key--wide");
        }
        btn.textContent = key === "BACK" ? "⌫" : key === "ENTER" ? "ENTER" : key;
        if (key === "BACK") btn.setAttribute("aria-label", "Backspace");
        else if (key === "ENTER") btn.setAttribute("aria-label", "Enter guess");
        else btn.setAttribute("aria-label", `Letter ${key}`);
        btn.addEventListener("click", () => handleKeyInput(key));
        rowEl.appendChild(btn);
        keyElCache.set(key, btn);
      });
      keyboardEl.appendChild(rowEl);
    });
  }

  // State priority so a key never downgrades from a better discovered state.
  const STATE_RANK = { absent: 1, present: 2, correct: 3 };

  function setKeyState(letter, newState) {
    const currentState = state.keyStates[letter];
    if (currentState && STATE_RANK[currentState] >= STATE_RANK[newState]) {
      return; // never downgrade an already-confirmed key
    }
    state.keyStates[letter] = newState;
    const keyEl = keyElCache.get(letter);
    if (keyEl) keyEl.dataset.state = newState;
  }

  function resetKeyboardStates() {
    state.keyStates = {};
    keyElCache.forEach((el) => {
      delete el.dataset.state;
    });
  }

  // Locks/unlocks all input (physical + on-screen) while a guess is
  // being evaluated/animated, so rapid taps or key-repeat can't submit
  // multiple guesses or race the reveal animation.
  function setInputLocked(locked) {
    state.isEvaluating = locked;
    keyboardEl.classList.toggle("is-locked", locked);
    keyboardEl.setAttribute("aria-busy", String(locked));
  }

  /* ---------------------------------------------------------
     STATUS BAR
     --------------------------------------------------------- */

  function showStatus(message, isError) {
    statusBarEl.textContent = message;
    statusBarEl.classList.toggle("status-error", Boolean(isError));
    clearTimeout(statusTimeout);
    if (message) {
      statusTimeout = setTimeout(() => {
        statusBarEl.textContent = "";
        statusBarEl.classList.remove("status-error");
      }, 1800);
    }
  }

  /* ---------------------------------------------------------
     ACCESSIBILITY ANNOUNCEMENTS
     --------------------------------------------------------- */

  function announce(message) {
    if (!srAnnouncerEl) return;
    srAnnouncerEl.textContent = "";
    // Re-set on next tick so repeated identical messages still fire.
    setTimeout(() => {
      srAnnouncerEl.textContent = message;
    }, 30);
  }

  function announceGuessResult(guess, result) {
    const counts = { correct: 0, present: 0, absent: 0 };
    result.forEach((r) => counts[r]++);
    announce(
      `${guess}: ${counts.correct} correct, ${counts.present} present, ${counts.absent} not in word.`
    );
  }

  /* ---------------------------------------------------------
     TIMER
     --------------------------------------------------------- */

  function formatTime(totalSeconds) {
    const mins = Math.floor(totalSeconds / 60)
      .toString()
      .padStart(2, "0");
    const secs = (totalSeconds % 60).toString().padStart(2, "0");
    return `${mins}:${secs}`;
  }

  function startTimerIfNeeded() {
    if (state.startTime !== null) return;
    state.startTime = Date.now();
    state.timerInterval = setInterval(() => {
      state.elapsedSeconds = Math.floor((Date.now() - state.startTime) / 1000);
      timerValueEl.textContent = formatTime(state.elapsedSeconds);
    }, 250);
  }

  function stopTimer() {
    if (state.timerInterval) {
      clearInterval(state.timerInterval);
      state.timerInterval = null;
    }
  }

  /* ---------------------------------------------------------
     GAME LOGIC
     --------------------------------------------------------- */

  /**
   * Deterministically picks today's word from TARGET_WORDS using the
   * number of UTC days since a fixed epoch. Every player's device
   * computes the same day-index for the same calendar date, so the
   * daily word matches for everyone without any server or account.
   */
  function getDailyChallenge() {
    const now = new Date();
    const utcMidnight = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
    const dayNumber = Math.floor((utcMidnight - DAILY_EPOCH_MS) / 86400000) + 1;
    const index =
      ((dayNumber - 1) % TARGET_WORDS.length + TARGET_WORDS.length) %
      TARGET_WORDS.length;
    return { index, dayNumber };
  }

  function pickTargetWord() {
    if (state.mode === "daily") {
      const { index, dayNumber } = getDailyChallenge();
      // Capture this game's Daily day identity at pick-time (i.e. game
      // start). Everything that needs to know which Daily this game
      // belongs to later (saving the completion record, the share
      // header) reads this captured value instead of recomputing the
      // day from the clock, so a game that crosses UTC midnight stays
      // tied to the day it started on.
      state.dailyDayNumber = dayNumber;
      return TARGET_WORDS[index].toUpperCase();
    }
    const idx = Math.floor(Math.random() * TARGET_WORDS.length);
    return TARGET_WORDS[idx].toUpperCase();
  }

  // True if there's an in-progress Random game (a guess submitted or a
  // letter typed) that a New Game / mode switch would silently discard.
  // Daily is exempt: an in-progress Daily can't be abandoned anyway
  // (switching away and back just resumes it), so it never needs to ask.
  function hasUnsavedRandomProgress() {
    return (
      state.mode === "random" &&
      !state.gameOver &&
      (state.guesses.length > 0 || state.currentGuess.length > 0)
    );
  }

  function confirmDiscardIfNeeded() {
    if (!hasUnsavedRandomProgress()) return true;
    return window.confirm("Abandon your current game and start a new one?");
  }

  function setMode(mode) {
    if (mode !== "random" && mode !== "daily") return;
    if (state.mode === mode) return;
    if (!confirmDiscardIfNeeded()) return;
    state.mode = mode;
    updateModeUI();
    startNewGame();
  }

  function updateModeUI() {
    const isDaily = state.mode === "daily";
    modeRandomBtn.setAttribute("aria-pressed", String(!isDaily));
    modeDailyBtn.setAttribute("aria-pressed", String(isDaily));

    const completedToday = Boolean(getTodayDailyRecord());
    modeDailyBtn.classList.toggle("is-completed", completedToday);

    if (isDaily) {
      // "Daily N" shows the current win streak: N successful Daily
      // completions in a row, reset to 0 by any Daily loss.
      modeDailyBtn.textContent = `Daily ${loadDailyStreak()}`;
    } else {
      modeDailyBtn.textContent = "DAILY";
    }
  }

  function startNewGame() {
    stopTimer();
    // Bump the game token so any in-flight timers from the previous
    // game (tile reveal staggering, the end-of-game timeout) see a
    // stale token and bail out instead of touching the new game's
    // board/keyboard/stats — this is what makes New Game safe to press
    // at any point, including mid-animation.
    state.gameToken += 1;
    hideDailyBanner();

    // If today's Daily challenge is already completed, never generate
    // a fresh attempt — restore the completed board instead. This is
    // what makes NEW GAME / PLAY AGAIN / re-selecting DAILY all safe
    // no-ops once today's Daily is done.
    if (state.mode === "daily") {
      const record = getTodayDailyRecord();
      if (record) {
        restoreCompletedDaily(record);
        return;
      }
    }

    state.target = pickTargetWord();
    state.guesses = [];
    state.results = [];
    state.currentGuess = "";
    state.row = 0;
    state.gameOver = false;
    state.won = false;
    state.startTime = null;
    state.elapsedSeconds = 0;

    buildBoard();
    resetKeyboardStates();
    setInputLocked(false);
    attemptsValueEl.textContent = `0 / ${MAX_ATTEMPTS}`;
    timerValueEl.textContent = "00:00";
    showStatus("");
    hideModal(resultModal);
    fitBoardToViewport();
  }

  // Rebuilds the board/keyboard to reflect an already-completed Daily
  // challenge, instantly (no reveal animation) and with input locked
  // via state.gameOver — the same guard handleKeyInput already uses
  // for a normally-finished game. The target word is recomputed via
  // pickTargetWord() rather than read from storage, since it's always
  // deterministically derivable and doesn't need to be persisted.
  function restoreCompletedDaily(record) {
    state.target = pickTargetWord();
    // pickTargetWord() already sets this from the live clock, but pin it
    // explicitly to the record's own day for clarity/safety — this is
    // the day the completed game actually belongs to.
    state.dailyDayNumber = record.dayNumber;
    state.guesses = record.guesses.slice();
    state.results = record.results.map((r) => r.slice());
    state.currentGuess = "";
    state.row = record.attemptsUsed;
    state.gameOver = true;
    state.won = record.won;
    state.startTime = null;
    state.elapsedSeconds = record.elapsedSeconds;

    buildBoard();
    resetKeyboardStates();

    for (let r = 0; r < record.attemptsUsed; r++) {
      const guess = record.guesses[r];
      const result = record.results[r];
      for (let c = 0; c < WORD_LENGTH; c++) {
        const tile = getTile(r, c);
        const letter = guess[c];
        tile.textContent = letter;
        tile.dataset.filled = "true";
        tile.dataset.state = result[c];
        tile.setAttribute("aria-label", `Row ${r + 1}, letter ${c + 1}, ${letter}, ${result[c]}`);
        setKeyState(letter, result[c]);
      }
    }

    setInputLocked(false);
    attemptsValueEl.textContent = `${record.attemptsUsed} / ${MAX_ATTEMPTS}`;
    timerValueEl.textContent = formatTime(record.elapsedSeconds);
    showStatus("");
    hideModal(resultModal);
    showDailyBanner(record);
    fitBoardToViewport();
  }

  /**
   * Evaluate a guess against the target word.
   *
   * Handles duplicate letters correctly using a two-pass approach:
   *  Pass 1: mark exact position matches as "correct" and consume
   *          one occurrence of that letter from the target's pool.
   *  Pass 2: for remaining letters, mark "present" only if there is
   *          still an unconsumed occurrence of that letter left in
   *          the target's pool, then consume it. Otherwise "absent".
   *
   * This ensures that if the guess has more copies of a letter than
   * the target actually contains, only the correct number of tiles
   * light up (green first, then yellow), and the rest are marked
   * absent — matching standard Wordle duplicate-letter behavior.
   */
  function evaluateGuess(guess, target) {
    const result = new Array(WORD_LENGTH).fill("absent");
    const targetLetters = target.split("");
    const letterPool = {};

    // Build a pool of letter counts from the target word.
    targetLetters.forEach((letter) => {
      letterPool[letter] = (letterPool[letter] || 0) + 1;
    });

    // Pass 1: exact matches first, consuming from the pool.
    for (let i = 0; i < WORD_LENGTH; i++) {
      if (guess[i] === targetLetters[i]) {
        result[i] = "correct";
        letterPool[guess[i]] -= 1;
      }
    }

    // Pass 2: remaining letters — present if pool still has copies left.
    for (let i = 0; i < WORD_LENGTH; i++) {
      if (result[i] === "correct") continue;
      const letter = guess[i];
      if (letterPool[letter] > 0) {
        result[i] = "present";
        letterPool[letter] -= 1;
      } else {
        result[i] = "absent";
      }
    }

    return result;
  }

  function handleKeyInput(key) {
    // Blocked once the game has ended, and blocked while a submitted
    // guess is still being evaluated/animated (prevents double-submits,
    // rapid-tap races, and typing into a row that's mid-flip).
    if (state.gameOver || state.isEvaluating) return;

    if (key === "ENTER") {
      submitGuess();
      return;
    }
    if (key === "BACK") {
      removeLetter();
      return;
    }
    if (/^[A-Z]$/.test(key)) {
      addLetter(key);
    }
  }

  function addLetter(letter) {
    if (state.currentGuess.length >= WORD_LENGTH) return;
    startTimerIfNeeded();
    state.currentGuess += letter;
    const col = state.currentGuess.length - 1;
    const tile = getTile(state.row, col);
    tile.textContent = letter;
    tile.dataset.filled = "true";
    tile.dataset.pop = "true";
    tile.setAttribute("aria-label", `Row ${state.row + 1}, letter ${col + 1}, ${letter}`);
    setTimeout(() => delete tile.dataset.pop, 150);
  }

  function removeLetter() {
    if (state.currentGuess.length === 0) return;
    const col = state.currentGuess.length - 1;
    const tile = getTile(state.row, col);
    tile.textContent = "";
    tile.dataset.filled = "false";
    tile.setAttribute("aria-label", `Row ${state.row + 1}, letter ${col + 1}, empty`);
    state.currentGuess = state.currentGuess.slice(0, -1);
  }

  function submitGuess() {
    if (state.currentGuess.length < WORD_LENGTH) {
      showStatus("NOT ENOUGH LETTERS", true);
      shakeRow(state.row);
      return;
    }

    if (!VALID_WORDS.has(state.currentGuess.toLowerCase())) {
      showStatus("NOT IN WORD LIST", true);
      shakeRow(state.row);
      return;
    }

    const guess = state.currentGuess;
    const result = evaluateGuess(guess, state.target);
    state.guesses.push(guess);
    state.results.push(result);

    // Lock all input for the duration of the reveal animation. Captured
    // token lets any in-flight timers detect a New Game reset and bail
    // out instead of mutating a game that's already been replaced.
    setInputLocked(true);
    const token = state.gameToken;
    const row = state.row;

    revealRow(row, guess, result, token);
    announceGuessResult(guess, result);

    const didWin = result.every((r) => r === "correct");
    const attemptsUsed = row + 1;
    attemptsValueEl.textContent = `${attemptsUsed} / ${MAX_ATTEMPTS}`;

    const isLastAttempt = attemptsUsed === MAX_ATTEMPTS;

    // Delay end-of-game / unlock handling until the full staggered
    // flip animation finishes, so input stays locked for exactly the
    // duration of the evaluation animation — never an arbitrary
    // unrelated timeout.
    const revealDuration = getRowRevealDuration();

    setTimeout(() => {
      if (token !== state.gameToken) return; // a New Game started meanwhile

      if (didWin) {
        state.gameOver = true;
        state.won = true;
        setInputLocked(false);
        endGame(true, attemptsUsed);
      } else if (isLastAttempt) {
        state.gameOver = true;
        state.won = false;
        setInputLocked(false);
        endGame(false, attemptsUsed);
      } else {
        state.row += 1;
        state.currentGuess = "";
        setInputLocked(false);
      }
    }, revealDuration);
  }

  const TILE_STAGGER_MS = 120; // delay between each tile's flip starting
  const TILE_FLIP_MS = 420; // duration of a single tile's flip animation
  // Total reveal for a 5-letter row: (5-1)*120 + 420 = 900ms — snappier
  // than the previous 1.46s while keeping the flip itself smooth.

  // When the user prefers reduced motion, the CSS collapses animation
  // durations to ~0, so the JS-side stagger/lock timing should match —
  // otherwise input would stay locked ~900ms after tiles have already
  // visually finished (a mismatch, though not a functional break).
  function prefersReducedMotion() {
    return (
      typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    );
  }

  function revealRow(row, guess, result, token) {
    const stagger = prefersReducedMotion() ? 0 : TILE_STAGGER_MS;
    for (let c = 0; c < WORD_LENGTH; c++) {
      const tile = getTile(row, c);
      const letter = guess[c];
      const letterState = result[c];

      // Stagger each tile's reveal so they flip left-to-right in sequence.
      setTimeout(() => {
        // If New Game was pressed mid-animation, this row's board may
        // have already been rebuilt/rescoped — skip touching it.
        if (token !== state.gameToken) return;
        tile.dataset.state = letterState;
        tile.setAttribute("aria-label", `Row ${row + 1}, letter ${c + 1}, ${letter}, ${letterState}`);
      }, c * stagger);

      // Update the on-screen keyboard as soon as the row is scored,
      // so the keyboard doesn't lag behind by a full reveal cycle.
      setKeyState(letter, letterState);
    }
  }

  function getRowRevealDuration() {
    if (prefersReducedMotion()) return 60; // small safety margin, not a full animation wait
    return (WORD_LENGTH - 1) * TILE_STAGGER_MS + TILE_FLIP_MS;
  }

  function shakeRow(row) {
    const rowEl = getRowEl(row);
    rowEl.dataset.shake = "true";
    setTimeout(() => delete rowEl.dataset.shake, 320);
  }

  function endGame(didWin, attemptsUsed) {
    stopTimer();
    recordResult(didWin, attemptsUsed, state.mode);

    if (state.mode === "daily") {
      // Use the day this game actually started on (captured in
      // pickTargetWord() at game start), NOT whatever getDailyChallenge()
      // would return right now — otherwise a game played across UTC
      // midnight would get filed under the new day's Daily instead of
      // the one it was actually playing.
      const dayNumber = state.dailyDayNumber ?? getDailyChallenge().dayNumber;
      saveDailyRecord({
        dayNumber,
        won: didWin,
        attemptsUsed,
        elapsedSeconds: state.elapsedSeconds,
        guesses: state.guesses.slice(),
        results: state.results.map((r) => r.slice()),
      });

      // Daily win streak: increments on a win, resets on a loss.
      if (didWin) {
        saveDailyStreak(loadDailyStreak() + 1);
      } else {
        saveDailyStreak(0);
      }

      updateModeUI(); // refresh the DAILY button's completed indicator + streak
    }

    showResultModal(didWin, attemptsUsed);
  }

  /* ---------------------------------------------------------
     MODALS
     Basic focus trap + Escape-to-close for accessibility, without
     changing the visual design.
     --------------------------------------------------------- */

  let lastFocusedEl = null;

  function getFocusableEls(container) {
    return Array.from(
      container.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      )
    ).filter((el) => !el.disabled && el.offsetParent !== null);
  }

  function modalKeyHandler(e) {
    const openModalEl = document.querySelector(".modal-overlay:not(.hidden)");
    if (!openModalEl) return;

    if (e.key === "Escape") {
      e.preventDefault();
      closeModal(openModalEl);
      return;
    }

    if (e.key === "Tab") {
      const focusables = getFocusableEls(openModalEl);
      if (!focusables.length) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  }

  // Note: the keydown listener for Tab-trapping/Escape is attached ONCE
  // (in wireEvents) rather than per open/close, so repeatedly opening
  // modals never accumulates duplicate listeners.
  function openModal(modalEl) {
    lastFocusedEl = document.activeElement;
    modalEl.classList.remove("hidden");
    const focusables = getFocusableEls(modalEl);
    (focusables[0] || modalEl).focus();
  }

  function closeModal(modalEl) {
    modalEl.classList.add("hidden");
    if (lastFocusedEl && typeof lastFocusedEl.focus === "function") {
      lastFocusedEl.focus();
    }
  }

  // Simple hide (no focus restore) — used when a game restart implicitly
  // dismisses the result modal rather than the user explicitly closing it.
  function hideModal(modalEl) {
    modalEl.classList.add("hidden");
  }

  // Builds one "<label> <value>" row for the result modal using
  // textContent (not innerHTML) for the dynamic value, so nothing
  // relies on string-interpolated markup.
  function createResultRow(label, value) {
    const row = document.createElement("div");
    row.className = "result-row";
    const labelEl = document.createElement("span");
    labelEl.textContent = label;
    const valueEl = document.createElement("span");
    valueEl.textContent = value;
    row.appendChild(labelEl);
    row.appendChild(valueEl);
    return row;
  }

  function showResultModal(didWin, attemptsUsed) {
    resultTitle.textContent = didWin ? "ACCESS GRANTED" : "ACCESS DENIED";
    resultTitle.classList.toggle("is-win", didWin);
    resultTitle.classList.toggle("is-loss", !didWin);

    const timeStr = formatTime(state.elapsedSeconds);
    shareStatusEl.textContent = "";

    const rows = didWin
      ? [
          ["Attempts", `${attemptsUsed} / ${MAX_ATTEMPTS}`],
          ["Time", timeStr],
          ["Word", state.target],
        ]
      : [
          ["Word", state.target],
          ["Attempts", `${attemptsUsed} / ${MAX_ATTEMPTS}`],
          ["Time", timeStr],
        ];

    resultBody.replaceChildren();
    rows.forEach(([label, value]) => {
      resultBody.appendChild(createResultRow(label, value));
    });

    announce(
      didWin
        ? `Access granted. Solved in ${attemptsUsed} attempts, ${timeStr}.`
        : `Access denied. The word was ${state.target}.`
    );

    openModal(resultModal);
  }

  /* ---------------------------------------------------------
     SHARE RESULT
     Builds a spoiler-free emoji grid (only ever called once the
     game is over, so this never reveals the target word early).
     --------------------------------------------------------- */

  function cellToEmoji(cellState) {
    if (cellState === "correct") return "🟩";
    if (cellState === "present") return "🟨";
    return "⬛";
  }

  function buildShareText() {
    const scoreLine = state.won ? `${state.guesses.length}/${MAX_ATTEMPTS}` : `X/${MAX_ATTEMPTS}`;
    const timeStr = formatTime(state.elapsedSeconds);

    let header = "DECODE";
    if (state.mode === "daily") {
      // Same captured-at-start day number as endGame()'s save, so the
      // share text always reflects the Daily this game actually was,
      // even if it was finished after a UTC midnight rollover.
      const dayNumber = state.dailyDayNumber ?? getDailyChallenge().dayNumber;
      header = `DECODE — DAILY #${String(dayNumber).padStart(3, "0")}`;
    }

    const grid = state.results
      .map((row) => row.map(cellToEmoji).join(""))
      .join("\n");

    return `${header}\n${scoreLine}  ${timeStr}\n\n${grid}`;
  }

  // Attempts the legacy execCommand('copy') fallback. Returns true only
  // if the copy actually succeeded — never reports false success.
  function fallbackCopy(text) {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    let succeeded = false;
    try {
      succeeded = document.execCommand("copy");
    } catch (e) {
      succeeded = false;
    }
    document.body.removeChild(textarea);
    return succeeded;
  }

  function showShareStatus(message, isError) {
    shareStatusEl.textContent = message;
    shareStatusEl.classList.toggle("share-status--error", Boolean(isError));
    setTimeout(() => {
      shareStatusEl.textContent = "";
      shareStatusEl.classList.remove("share-status--error");
    }, 2200);
  }

  async function shareResult() {
    const text = buildShareText();

    if (navigator.share) {
      try {
        await navigator.share({ text });
        return;
      } catch (e) {
        if (e && e.name === "AbortError") return; // user cancelled the share sheet
        // fall through to clipboard on any other share failure
      }
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        showShareStatus("RESULT COPIED");
        return;
      } catch (e) {
        // fall through to the legacy fallback below
      }
    }

    // Only report success if the legacy copy actually worked — never
    // claim a copy happened when every method failed.
    if (fallbackCopy(text)) {
      showShareStatus("RESULT COPIED");
    } else {
      showShareStatus("COULDN'T COPY — COPY MANUALLY", true);
    }
  }

  /* ---------------------------------------------------------
     EVENT WIRING
     --------------------------------------------------------- */

  function wireEvents() {
    document.addEventListener("keydown", (e) => {
      const anyModalOpen = document.querySelector(".modal-overlay:not(.hidden)");
      if (anyModalOpen) return; // ignore game input while any modal is open
      const key = e.key.toUpperCase();
      if (key === "ENTER") {
        handleKeyInput("ENTER");
      } else if (key === "BACKSPACE") {
        handleKeyInput("BACK");
      } else if (/^[A-Z]$/.test(key)) {
        handleKeyInput(key);
      }
    });

    // Single, permanent listener for modal Tab-trapping and Escape-to-close.
    document.addEventListener("keydown", modalKeyHandler);

    newGameBtn.addEventListener("click", () => {
      if (confirmDiscardIfNeeded()) startNewGame();
    });
    modalPlayAgain.addEventListener("click", startNewGame);
    shareBtn.addEventListener("click", shareResult);

    modeRandomBtn.addEventListener("click", () => setMode("random"));
    modeDailyBtn.addEventListener("click", () => setMode("daily"));

    if (dailyBannerViewBtn) {
      dailyBannerViewBtn.addEventListener("click", () => {
        // Reopens the same result modal a normal finish would show,
        // using the already-restored state (target/elapsed/guesses).
        showResultModal(state.won, state.guesses.length);
      });
    }

    statsBtn.addEventListener("click", () => {
      renderStats();
      openModal(statsModal);
    });
    statsClose.addEventListener("click", () => closeModal(statsModal));
    statsModal.addEventListener("click", (e) => {
      if (e.target === statsModal) closeModal(statsModal);
    });

    let resizeTimeout = null;
    const onViewportChange = () => {
      clearTimeout(resizeTimeout);
      resizeTimeout = setTimeout(fitBoardToViewport, 120);
    };
    window.addEventListener("resize", onViewportChange);
    window.addEventListener("orientationchange", onViewportChange);
    if (window.visualViewport) {
      window.visualViewport.addEventListener("resize", onViewportChange);
    }
  }

  /* ---------------------------------------------------------
     INIT
     --------------------------------------------------------- */

  function init() {
    buildBoard();
    buildKeyboard();
    renderStats();
    updateModeUI();
    wireEvents();
    startNewGame();
    // Run once more after layout settles (fonts/safe-area insets can
    // shift measured heights slightly right after first paint).
    requestAnimationFrame(fitBoardToViewport);
  }

  document.addEventListener("DOMContentLoaded", function () {
    (window.__decodeSyncReady || Promise.resolve()).then(init);
  });

  /* Service worker registration removed: this copy of DECODE runs
     embedded inside the KRAGVOR app (as an iframe under /apps/decode),
     which already has its own service worker covering the whole origin.
     A second one scoped under /decode/ would just create cache-scope
     conflicts with no benefit here. */
})();
