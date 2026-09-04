//! The run-key wordlists (task `cb6c9da`).
//!
//! **Static data. No engine code depends on this module at v1**, and nothing
//! here touches the frozen DDL, the projector or conformance. It exists
//! because the structured run key of `508dd9e` / `62a6a09` §3 has exactly one
//! genuinely new artifact, and this is it.
//!
//! ## What the lists are for
//!
//! The design uses a key like `scout-chair-a748b2`: `scout` is the visible
//! **handle**, `chair` is the **disambiguator**, `scout-chair` is the stable
//! `agent_key`, and `a748b2` is the run's short id. Position is structural, so
//! there are two lists and not one — [`HANDLES`] supplies the handle and
//! [`DISAMBIGUATORS`] supplies the disambiguator.
//!
//! ## The property, and why it is the whole point
//!
//! A structured token often looks broken when garbled; a word key can remain
//! visually plausible. Misremember `scout-chair-a748b2` as
//! `scout-chiar-a748b2` and the typo may escape a human glance, but validation
//! rejects it. The distance floor below makes `chair` the one unambiguous
//! repair rather than allowing the typo to collide with another legal key.
//!
//! So both lists satisfy, **within** each list (there is no cross-list
//! constraint, because position is structural):
//!
//! > pairwise Damerau-Levenshtein distance >= 3
//!
//! Damerau rather than plain Levenshtein because transposition (`chiar` for
//! `chair`) is among the commonest garbles and plain Levenshtein scores it 2.
//! Unrestricted Damerau-Levenshtein rather than the optimal-string-alignment
//! variant, because OSA is an upper bound on true DL — so a floor on true DL
//! is the strictly stronger claim, and unlike OSA it is a real metric.
//!
//! A floor of 3 buys more than "a typo is invalid":
//!
//! | Minimum distance | Guarantees |
//! |---|---|
//! | >= 2 | a single-character error cannot turn one valid word into another |
//! | **>= 3** | any two-character error is still detected — **and any single-character error is correctable**, because the garbled string has exactly one nearest valid word |
//!
//! The second property is the useful one: a mangled key can be *repaired*
//! rather than merely rejected, so the loud failure arrives with a suggested
//! fix instead of a dead end.
//!
//! **The property is enforced, not asserted.** `tests/records/wordlist.rs` recomputes
//! every pair on every run. The check is O(n^2) on 768 short strings, which is
//! cheap, and the artifact is permanent, so it is worth pinning rather than
//! trusting.
//!
//! ## How the lists were built
//!
//! Hand-curated candidate pools, grouped by semantic domain, greedily reduced
//! to the distance floor. Greedy rather than exact: this is a one-off static
//! artifact, not an optimisation problem worth solving to optimality.
//!
//! Greedy is order-sensitive — of a colliding pair the first word survives —
//! so the pools are ordered most-familiar-first, by authoring pass and then
//! round-robin across domains *within* every pass, top-up passes included. A
//! pass held as one flat list silently opts out of the round-robin, which is
//! how an early revision ranked `skua` and `fulmar` above `orbit` and `prism`
//! and made the claim below — that the truncated tail is the least familiar
//! end — untrue. **No external frequency corpus is involved.**
//! An earlier revision ordered by rank from `google-10000-english`, which
//! derives from the Google Web Trillion Word Corpus distributed by the LDC;
//! its licence restricts use to education and research, and this repository is
//! to be made public. The ranks were removed rather than relied on. They were
//! doing less than they appeared to: exactly three candidates were validated
//! by the frequency list and not by the dictionary, and the achieved sizes
//! went *up* slightly without them. Curation was always doing the work.
//!
//! Filtered for: the 4-7 character band; function words; inflections of
//! another candidate; homophones (`sale`/`sail`, `peace`/`piece`) — edit
//! distance cannot catch those and the key gets spoken aloud; **US/UK
//! spelling variants** (`harbor`/`harbour`, `theatre`/`theater`), which are
//! the same silent-failure mode arriving by a different door and which the
//! source records do not mention; and terms unsuitable to hand someone at
//! random.
//!
//! The handle list is filtered harder than the disambiguator list, because a handle
//! is a *name* — it is what a person says out loud about the agent, and what
//! `SELECT DISTINCT` makes a roster from. Beyond the above it excludes words
//! that read as a person's given name (`holly`, `rowan` — ambiguous in a
//! workspace full of records about people), words that are pejorative applied
//! to an actor (`weasel`, `censor`), and words too specialist for anyone to
//! *choose* (`gadwall`, `tuyere`, `esker`). The disambiguator list keeps a lower
//! bar deliberately: it only has to be memorable enough to retype.
//!
//! ## Sizes, and what they buy
//!
//! The distance floor permits 259 handles and 517 disambiguators from the
//! curated pools. The lists ship truncated to **256** and **512** — the tail
//! is the least familiar end, so the truncation costs nothing the design
//! wanted and makes the arithmetic exact:
//!
//! - `256 * 512` = **131,072** stable agent keys
//! - `32^6` = **1,073,741,824** run ids per agent key
//!
//! Server minting checks prior durable events and the removable read log before
//! returning a candidate, so the short-id space is convenience rather than a
//! registry or liveness mechanism.
//!
//! Note the words that appear on both lists (`copse`, `orbit`, `sextant`, …).
//! That is not an oversight: position is structural, the parser splits on the
//! first hyphen, and `scout-scout-heron` is a perfectly valid key. Forcing the
//! lists disjoint would cost good disambiguators to buy a cosmetic property.

/// The agent handle. Persistent, reusable, human-facing.
///
/// Pairwise Damerau-Levenshtein distance >= 3, enforced by
/// `tests/records/wordlist.rs`.
pub const HANDLES: [&str; 256] = [
    "scout", "heron", "anvil", "delta", "quartz", "zephyr", "ranger", "otter", "chisel", "ridge",
    "basalt", "warden", "mallet", "mesa", "marble", "monsoon", "pilot", "falcon", "wrench",
    "fjord", "slate", "cyclone", "mason", "osprey", "pliers", "butte", "tempest", "smith",
    "canyon", "flint", "squall", "herald", "ermine", "gorge", "breeze", "envoy", "rasp", "gypsum",
    "comet", "scribe", "beaver", "bluff", "nebula", "cooper", "pyrite", "quasar", "ibex", "trowel",
    "crag", "sickle", "knoll", "cobalt", "zenith", "puma", "scythe", "moor", "tapir", "hammer",
    "aurora", "tongs", "gecko", "copse", "pewter", "eclipse", "sailor", "viper", "kiln", "sentry",
    "cobra", "marsh", "cedar", "raven", "spindle", "dune", "alder", "equinox", "steward", "magpie",
    "shuttle", "shoal", "birch", "curator", "plover", "needle", "reef", "courier", "curlew",
    "thimble", "willow", "halo", "compass", "aspen", "cirrus", "sextant", "inlet", "cumulus",
    "driver", "caliper", "spruce", "stratus", "hunter", "kestrel", "nimbus", "tracker", "merlin",
    "loch", "harrier", "ruler", "stencil", "brook", "gannet", "scalpel", "puffin", "lantern",
    "geyser", "beacon", "egret", "anchor", "carver", "turner", "stork", "tiller", "onyx", "joiner",
    "cleat", "summit", "opal", "swift", "saddle", "plumber", "pulley", "thrush", "beryl", "glen",
    "bunting", "pumice", "brewer", "wagtail", "sparrow", "kettle", "drummer", "divider", "terrace",
    "mallard", "resin", "lacquer", "bailiff", "vellum", "sheriff", "linen", "sieve", "prefect",
    "granite", "lapwing", "consul", "snipe", "tribune", "buzzard", "plateau", "walnut", "oracle",
    "stylus", "upland", "goshawk", "lowland", "hickory", "adept", "poplar", "novice", "wetland",
    "juniper", "cypress", "squire", "redwood", "mink", "whisk", "prairie", "mortar", "steppe",
    "tundra", "vole", "clamp", "savanna", "outback", "forager", "lagoon", "sapper", "newt",
    "estuary", "pioneer", "hatchet", "machete", "bosun", "shears", "cobbler", "crowbar", "pike",
    "minnow", "spanner", "grocer", "bobbin", "herder", "flask", "cricket", "keeper", "cicada",
    "finder", "mantis", "sifter", "jaguar", "leopard", "cheetah", "builder", "ocelot", "lemur",
    "scholar", "gibbon", "tutor", "macaque", "mentor", "captain", "gazelle", "impala", "ensign",
    "recruit", "veteran", "narwhal", "beluga", "orca", "manatee", "condor", "eagle", "pelican",
    "deputy", "piston", "artisan", "turbine", "gull", "dynamo", "painter", "bobcat", "prism",
    "orbit", "coyote", "pilgrim", "nomad", "fawn", "roebuck", "chamois", "marmot", "rabbit",
    "muskrat", "admiral", "possum", "wombat", "koala",
];

/// The disambiguator separating agents that share a handle.
///
/// Pairwise Damerau-Levenshtein distance >= 3, enforced by
/// `tests/records/wordlist.rs`.
pub const DISAMBIGUATORS: [&str; 512] = [
    "bread", "chair", "shirt", "tower", "wagon", "banjo", "river", "cloud", "finger", "amber",
    "answer", "gather", "racket", "letter", "circle", "toast", "table", "bridge", "barge",
    "fiddle", "stream", "frost", "donkey", "thumb", "evening", "azure", "wonder", "scatter",
    "parcel", "square", "lantern", "stool", "scarf", "tunnel", "canoe", "flute", "pond", "mule",
    "memory", "helmet", "stamp", "compass", "bench", "glove", "dome", "kayak", "oboe", "lake",
    "sleet", "elbow", "summer", "bronze", "promise", "skate", "hexagon", "beacon", "cheese",
    "couch", "socks", "vault", "sledge", "cello", "marsh", "drizzle", "coral", "settle", "album",
    "spiral", "anchor", "shelf", "harp", "meadow", "ankle", "autumn", "puzzle", "travel",
    "archery", "diary", "onion", "drawer", "vest", "steeple", "field", "rainbow", "crimson",
    "arrive", "journal", "trinket", "garlic", "closet", "turret", "stirrup", "drum", "sunset",
    "tongue", "month", "emerald", "depart", "rowing", "chapter", "fathom", "pepper", "sunrise",
    "rabbit", "voice", "decade", "golden", "sailing", "volume", "furlong", "sugar", "button",
    "organ", "century", "indigo", "pencil", "league", "mirror", "piano", "valley", "stride",
    "moment", "ivory", "weave", "javelin", "crayon", "atlas", "wolf", "glance", "minute", "lilac",
    "method", "stitch", "discus", "bushel", "collar", "octave", "island", "seal", "knuckle",
    "weekend", "maroon", "fasten", "hurdle", "quill", "gallon", "parade", "teapot", "smoke",
    "forearm", "holiday", "orange", "rhythm", "climb", "relay", "pageant", "grape", "ribbon",
    "cabin", "dolphin", "eyebrow", "descend", "jubilee", "lemon", "pebble", "kitten", "eyelash",
    "measure", "regatta", "binding", "recipe", "cottage", "chorus", "boulder", "flurry", "puppy",
    "scarlet", "drift", "formula", "sepia", "angling", "degree", "almanac", "cherry", "fork",
    "moss", "terrier", "wisdom", "radius", "knife", "denim", "whistle", "magenta", "carrot",
    "tray", "tweed", "thunder", "spaniel", "comfort", "reckon", "orchard", "potato", "flask",
    "flannel", "caravan", "tempest", "saffron", "welcome", "blouse", "plaza", "gondola", "violin",
    "wren", "bounce", "pasture", "sweater", "terrace", "twister", "crow", "sienna", "signal",
    "paddock", "broom", "balcony", "clipper", "guitar", "marker", "saunter", "deluge", "pigeon",
    "meander", "wheat", "apron", "tunic", "bicycle", "ukulele", "sunbeam", "symbol", "pillow",
    "tandem", "emblem", "soup", "castle", "trunk", "stew", "blanket", "citadel", "tractor",
    "banner", "inkwell", "trouser", "bastion", "trumpet", "twig", "pennant", "curtain", "rampart",
    "cornet", "humid", "rooster", "fortune", "palette", "beanie", "balmy", "legacy", "easel",
    "beret", "sultry", "tribute", "canvas", "wafer", "fedora", "satchel", "blossom", "brush",
    "attic", "turban", "duffel", "piccolo", "iris", "sparkle", "pigment", "cocoa", "granary",
    "valise", "tambour", "herring", "majesty", "varnish", "hearth", "visor", "silo", "whisper",
    "glimmer", "pottery", "mantel", "sandal", "spider", "murmur", "chimney", "marimba", "echo",
    "glazing", "silence", "ladder", "hutch", "ballad", "bramble", "buffalo", "mosaic", "galosh",
    "anthem", "harmony", "nutmeg", "muffler", "gazebo", "lullaby", "alpaca", "reverie", "origami",
    "vanilla", "cushion", "veranda", "walnut", "poncho", "pergola", "sonata", "almond", "anorak",
    "masonry", "pecan", "parka", "belfry", "joinery", "cashew", "dresser", "cupola", "peanut",
    "rotunda", "sesame", "raisin", "pantry", "portico", "apricot", "atrium", "jasmine", "burrow",
    "goblet", "foundry", "pickle", "chalice", "gingham", "relish", "pitcher", "smithy", "tadpole",
    "biscuit", "muslin", "cowslip", "minnow", "chiffon", "brewery", "campion", "urchin", "pudding",
    "taffeta", "bakery", "sorrel", "custard", "brocade", "library", "damask", "museum", "comfrey",
    "gelato", "lichen", "praline", "fungus", "nougat", "studio", "toffee", "truffle", "fudge",
    "skillet", "foliage", "waffle", "pancake", "noodle", "pretzel", "sconce", "crouton", "lettuce",
    "spinach", "wick", "cabbage", "parsnip", "shallot", "pumpkin", "gourd", "soybean", "vinegar",
    "nectar", "sardine", "quince", "oasis", "penguin", "shovel", "guava", "jungle", "sturdy",
    "explore", "purse", "papaya", "glacier", "toucan", "galaxy", "imagine", "hallway", "banana",
    "sticker", "iceberg", "cosmos", "bargain", "doorway", "coconut", "volcano", "ostrich",
    "pyramid", "nimble", "gateway", "avocado", "peacock", "orbit", "bright", "damson", "seaweed",
    "magpie", "medlar", "rhubarb", "sunny", "spring", "chicory", "jolly", "endive", "lively",
    "quirky", "nail", "cress", "village", "snappy", "chive", "parsley", "rustic", "sherbet",
    "earnest", "ramekin", "spatula", "firefly", "cobweb", "prairie", "quartz", "bamboo", "trolley",
    "lanyard", "savanna", "granite", "juniper", "caramel", "toolbox", "seesaw", "beehive",
    "tundra", "rattan", "thermos", "anthill", "jasper", "rowboat", "skylark", "compote", "trellis",
    "estuary", "tartlet", "topaz", "linnet", "frolic", "dapple", "cavern", "dinghy", "puffin",
    "grotto", "awning", "abacus", "shingle", "freckle", "jackdaw", "anneal", "osprey", "fossil",
    "cradle", "peridot", "parfait", "lens", "holdall", "copse", "kestrel", "rebus", "spinney",
    "trough", "transom", "buoy", "sextant", "gherkin",
];

/// The floor both lists satisfy, within each list.
pub const MIN_DISTANCE: usize = 3;

/// Unrestricted Damerau-Levenshtein distance.
///
/// Unrestricted rather than the optimal-string-alignment variant: OSA forbids
/// editing a substring twice, which makes it an *upper bound* on true DL. A
/// floor checked against true DL is therefore the strictly stronger claim, and
/// unlike OSA it is a genuine metric.
///
/// It lives here rather than in the test because [`MIN_DISTANCE`] is not just a
/// property to verify — it is what makes REPAIR possible, and repair is engine
/// behaviour. At a floor of 3, any single-character garble has exactly one
/// nearest valid word, so `crate::runkey` can hand a mistyped key back with the
/// word it meant instead of a dead end. The test still pins this function
/// against known pairs before trusting it over 200k pairs of real data.
///
/// The textbook table with two sentinel rows and a last-seen-row map;
/// O(len(a) * len(b)) on strings of at most 7 characters.
pub fn damerau_levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (la, lb) = (a.len(), b.len());
    let max_dist = la + lb;

    // (la + 2) x (lb + 2), offset by two for the sentinels.
    let mut d = vec![vec![0usize; lb + 2]; la + 2];
    d[0][0] = max_dist;
    for i in 0..=la {
        d[i + 1][0] = max_dist;
        d[i + 1][1] = i;
    }
    for j in 0..=lb {
        d[0][j + 1] = max_dist;
        d[1][j + 1] = j;
    }

    // Last row in which each character was seen.
    let mut last_row: std::collections::HashMap<char, usize> = std::collections::HashMap::new();

    for i in 1..=la {
        // Last column in which a[i-1] matched, within this row.
        let mut last_match_col = 0usize;
        for j in 1..=lb {
            let k = *last_row.get(&b[j - 1]).unwrap_or(&0);
            let l = last_match_col;
            let cost = if a[i - 1] == b[j - 1] {
                last_match_col = j;
                0
            } else {
                1
            };
            d[i + 1][j + 1] = *[
                d[i][j] + cost,                          // substitution
                d[i + 1][j] + 1,                         // insertion
                d[i][j + 1] + 1,                         // deletion
                d[k][l] + (i - k - 1) + 1 + (j - l - 1), // transposition
            ]
            .iter()
            .min()
            .unwrap();
        }
        last_row.insert(a[i - 1], i);
    }

    d[la + 1][lb + 1]
}

/// The nearest word in `list`, and its distance — the repair half of the
/// distance floor.
pub fn nearest<'w>(word: &str, list: &[&'w str]) -> (&'w str, usize) {
    list.iter()
        .map(|candidate| (*candidate, damerau_levenshtein(word, candidate)))
        .min_by_key(|(_, distance)| *distance)
        .expect("wordlists are non-empty")
}
