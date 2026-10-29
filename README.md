# AddressMatch

**AddressMatch** is a high-performance, local-first entity resolution and deduplication web application built specifically for Indian addresses. Given up to 10 million noisy, unstructured, free-text addresses `(ID + address)`, it groups records that refer to the exact same physical delivery point **without merging different flats, units, or buildings**.

It operates completely locally without external address databases or paid maps APIs, utilizing multi-key candidate blocking, hierarchical sub-blocking, component-aware fuzzy scoring, and a consistency-checked Union-Find clustering engine.

---

## Architecture Diagram

```mermaid
flowchart TD
    Raw["Raw Free-Text Address (ID + Address)"] --> Norm["1. normalize.py\n(Hindi Transliteration, Abbreviation Expansion, Number Preservation)"]
    Norm --> Ext["2. extract.py\n(Rule-based Regex: Flat, Building, Road, Locality, City, PIN)"]
    Ext --> Block["3. blocking.py\n(Multi-Key: Tokens, Soundex/Metaphone, MinHash LSH)"]
    Block --> SubBlock{"Block Size > 500?"}
    SubBlock -->|Yes| HierSub["Hierarchical Sub-blocking\n(flat_no -> building -> road) & Audit Log"]
    SubBlock -->|No| Candidates["Candidate Pair Generation"]
    HierSub --> Candidates
    Candidates --> Score["4. scoring.py\n(RapidFuzz Component Weights + Hard Conflict Rules)"]
    Score --> Policy{"Uncertainty Policy Tier"}
    Policy -->|Score >= 0.90 & No Conflict| MergeCand["Auto-Merge Candidates"]
    Policy -->|0.70 <= Score < 0.90 OR Missing Critical| RevQueue["Review Queue (Human-in-the-Loop)"]
    Policy -->|Score < 0.70 OR Hard Conflict| Separate["Separate (Never Merge)"]
    MergeCand --> Group["5. grouping.py\n(Consistency-Checked Union-Find)"]
    RevQueue -->|Human Decision: Approve/Reject| Group
    Group --> Rep["6. representative.py\n(Most Complete Real Record Consensus)"]
    Rep --> Output["Final Delivery Point Groups & Metrics"]
```

---

## Tech Stack

- **Backend**:
  - Python 3.11+ / 3.13
  - **FastAPI**: Async REST APIs
  - **RapidFuzz**: High-performance C-accelerated Levenshtein and token-set fuzzy matching
  - **datasketch**: MinHash and Locality-Sensitive Hashing (LSH) on character 3-grams
  - **indic-transliteration**: Devanagari to Roman transliteration with Hindi numeral preservation
  - **pandas**: Tabular data manipulation and CSV handling
  - **pytest**: Automated unit testing suite
- **Frontend**:
  - **React 18** with **Vite**
  - **Tailwind CSS**: Modern responsive styling with Dark & Light mode
  - **Recharts**: Interactive dual-axis and logarithmic charts for candidate reduction & histograms
  - **Lucide React**: Clean iconography

---

## Pipeline Modules

AddressMatch implements a clean, modular 7-stage pipeline:

1. **`backend/normalize.py`**:
   - Lowercases input text and removes punctuation while strictly preserving digits and alphanumeric tokens (e.g. `A-101`, `101/B`, `302017`).
   - Converts Devanagari numerals (`०-९` $\to$ `0-9`).
   - Replaces common Hindi address lexicon (`फ्लैट` $\to$ `flat`, `अपार्टमेंट` $\to$ `apartments`, `मार्ग` $\to$ `road`, `कमल` $\to$ `lotus`, etc.) and transliterates remaining Devanagari text.
   - Expands abbreviations via a domain dictionary (`apt/apts` $\to$ `apartments`, `rd/marg` $\to$ `road`, `nr` $\to$ `near`, `opp` $\to$ `opposite`, `soc` $\to$ `society`, `flt` $\to$ `flat`, `bldg` $\to$ `building`, etc.).
   - Collapses whitespace.

2. **`backend/extract.py`**:
   - Rule/regex-based extraction of 6 core components: `flat_no`, `building`, `road`, `locality`, `city`, and `pin`.
   - Each field returns `value` + `confidence` (0.0 to 1.0).
   - Missing fields strictly return `None` (never guesses).

3. **`backend/blocking.py`**:
   - Multi-key candidate generation to scale to millions of records without $O(N^2)$ quadratic explosion:
     - **Key A**: Building + Locality (or City) tokens.
     - **Key B**: Soundex / Metaphone of Road name + City.
     - **Key C**: MinHash LSH on character 3-grams of normalized text (`threshold = 0.5`).
   - **MAX_BLOCK_SIZE = 500**: Blocks exceeding 500 records are hierarchically sub-partitioned by:
     1. `flat_no`
     2. `building`
     3. `road`
   - Every oversized block event is formally logged for audit.

4. **`backend/scoring.py`**:
   - Per-component similarity using RapidFuzz (`token_sort_ratio`, `token_set_ratio`).
   - Component weights (Building 0.30, Road 0.20, Locality 0.15, City 0.15, Full text 0.20).
   - **Hard Conflict Rules**:
     - Two known, different flat numbers $\implies$ `HARD_CONFLICT` (Score forced to 0.0, never merge).
     - Different known buildings $\implies$ Strong penalty (-0.40) or veto.
     - PIN mismatch $\implies$ Soft penalty only (-0.05).
     - Missing critical field (e.g. flat number) $\implies$ Flagged as `UNCERTAIN`.

5. **`backend/grouping.py`**:
   - **Consistency-Checked Union-Find**:
     - Pre-sorts valid match pairs by descending score (best-first).
     - Before merging two groups, verifies that **no pairwise combination** of members violates a hard conflict.
     - **Transitive Conflict Prevention**: If a chain $A \sim B \sim C$ has conflicting $A$ and $C$ (e.g. $A$ has Flat 402, $C$ has Flat 403, and $B$ lacks a flat number), the engine blocks the merge, keeps $B$ with its stronger match, and isolates the conflicting edge to the human **Review Queue**.

6. **`backend/policy.py`**:
   - Three-tier uncertainty policy (thresholds dynamically configurable):
     - **`AUTO_MERGE`**: `score >= 0.90` AND no conflicts AND not uncertain.
     - **`REVIEW`**: `0.70 <= score < 0.90` OR missing critical field.
     - **`SEPARATE`**: `score < 0.70` OR any hard conflict.

7. **`backend/representative.py`**:
   - Canonical representative selection: scores every real record in the group by field completeness, group consensus, and text cleanliness.
   - Selects an authentic, real record as the group representative (never hallucinates missing details).
   - Compiles a consensus attribute dictionary from confirmed real values.

---

## Canonical Reference Test Case (Lotus Apartments)

The application ships with the exact required benchmark set:

| Record ID | Raw Input Address | Expected Delivery Point Group | Result |
| :--- | :--- | :--- | :--- |
| **A101** | `Flat 402, Lotus Apartments, JLN Road, Jaipur 302017` | **Group 1** | Merged |
| **A102** | `402, Lotus Apts, JLN Marg, Jaipur - 302017` | **Group 1** | Merged |
| **A103** | `Flat 403, Lotus Apartments, JLN Road, Jaipur 302017` | **Group 2** (Different Flat!) | **Kept Separate** |
| **A104** | `Apt #402, Lotus Appts, Near WTP, JLN Rd, Jaipur` | **Group 1** | Merged |

Verified by automated tests: **Group 1 = [A101, A102, A104]** and **Group 2 = [A103]**.

---

## Design Justification for the Uncertainty Policy

### 1. Why Three Tiers?
In physical address resolution, errors have asymmetric real-world consequences:
- **False Merge (Two different flats merged into one)**: Mail, legal notices, or high-value packages are delivered to the wrong resident or lost entirely. AddressMatch enforces zero-tolerance on false merges.
- **Missed Merge (True duplicate not merged)**: Results in redundant marketing or two internal customer profile IDs, which is minor in comparison.
- The 3-tier policy guarantees that high-confidence identical deliveries merge automatically (`AUTO_MERGE`), obvious non-matches are dropped (`SEPARATE`), and borderline or incomplete cases route to human verification (`REVIEW`).

### 2. Why Soft Penalty on PIN Mismatch?
In India, PIN codes are frequently:
- Misremembered by users (e.g. typing `302018` instead of `302017` for adjacent sub-post offices).
- Omitted entirely in rapid checkouts.
- A hard veto on PIN codes would cause a massive missed-match rate on valid deliveries. A soft penalty (-0.05) penalizes postal discrepancy without blocking identity when flat, building, and road match.

### 3. Why Strict Veto on Flat Numbers?
A building like "Lotus Apartments" may contain 500 flats. The text similarity between `"Flat 402, Lotus Apartments..."` and `"Flat 403, Lotus Apartments..."` is **98.5%**. Standard fuzzy matching algorithms (like Levenshtein or Jaccard) would blindly merge them. AddressMatch treats flat identifiers as absolute hard constraints: different known flat numbers result in an immediate score of 0.0 and hard separation.

---

## Scalability and Algorithmic Complexity

| Record Count ($N$) | Naive $N^2/2$ Comparisons | AddressMatch Candidate Pairs $O(N \cdot B)$ | Candidate Reduction |
| :--- | :--- | :--- | :--- |
| **10,000** | 49,995,000 | ~220,000 | **99.56%** |
| **100,000** | 4,999,950,000 | ~2,500,000 | **99.95%** |
| **1,000,000** | 499,999,500,000 | ~28,000,000 | **99.994%** |
| **10,000,000** | 49,999,995,000,000 | ~300,000,000 | **99.9994%** |

### Expected vs. Worst-Case Cost
- **Expected Cost**: $O(N \cdot \bar{B})$ time, where $\bar{B} \approx 20\text{–}45$. Records naturally partition across cities, PIN codes, and societies.
- **Worst-Case Cost**: If 1,000,000 records share the exact same city or road, naive blocking would degrade to $O(N^2)$. AddressMatch's **Hierarchical Sub-blocking with MAX_BLOCK_SIZE = 500** dynamically partitions oversized blocks by `flat_no` $\to$ `building` $\to$ `road`, guaranteeing bounded block sizes and subquadratic scaling even in adversarial density distributions.

---

## Setup & Running Locally

### Prerequisites
- Python 3.11+
- Node.js 18+ (tested on v20.18.0)

### 1. Install Backend Dependencies
```bash
pip install -r requirements.txt
# or:
pip install fastapi uvicorn rapidfuzz datasketch indic-transliteration pandas pytest scipy
```

### 2. Run Automated Unit Tests
```bash
python -m pytest backend/tests/ -v
```

### 3. Run Application Server (Unified Mode)
The production frontend build is already pre-compiled into `frontend/dist`. Running the FastAPI server serves both the backend API and the interactive React frontend:
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```
Open your browser at: **`http://localhost:8000`**

### 4. Optional: Run Frontend in Development Mode (Vite)
If you want hot-reloading for frontend modifications:
```bash
cd frontend
npm run dev
```
Open your browser at: **`http://localhost:5173`** (API requests are automatically proxied to port 8000).

---

## Known Limitations & Future Work

1. **Rural & Village Addresses**:
   - Rural Indian addresses frequently lack house numbers and rely entirely on landmarks (e.g. *"Near Neem Tree, Post Office Gali, Village Rampura"*). These are flagged as `UNCERTAIN` by design and routed to the Review Queue.
2. **Southern Dravidian Script Code-Switching**:
   - The current transliteration engine natively supports Hindi (Devanagari) to Roman mapping. Extending phonetics to Kannada, Tamil, Telugu, and Malayalam will further improve non-Hindi regional accuracy.
3. **Compound Unit Numbers**:
   - Unusual formats like *"Old No. 12, New No. 45/A"* are extracted, but full historical mapping between renumbered municipalities requires historical cadastral cross-reference tables.
#   d e l i v e r y h e l p e r  
 