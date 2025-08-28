import string

def extract_pubmed_keywords(prompt: str) -> str:
    """
    Extracts relevant keywords from a prompt for a PubMed search.
    Removes stopwords, punctuation, and digits to create a clean query.
    """
    # A more comprehensive list of stopwords, including common conversational words
    stop_words = {
        "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "as", "at",
        "be", "because", "been", "before", "being", "below", "between", "both", "but", "by",
        "can", "could", "did", "do", "does", "doing", "down", "during",
        "each", "few", "for", "from", "further", "focusing",
        "had", "has", "have", "having", "he", "her", "here", "hers", "herself", "him", "himself", "his", "how",
        "i", "if", "in", "into", "is", "it", "its", "itself",
        "just", "me", "more", "most", "my", "myself",
        "no", "nor", "not", "now", "of", "off", "on", "once", "only", "or", "other", "our", "ours", "ourselves", "out", "over", "own",
        "same", "she", "should", "so", "some", "such",
        "than", "that", "the", "their", "theirs", "them", "themselves", "then", "there", "these", "they", "this", "those", "through", "to", "too",
        "under", "until", "up", "use",
        "very", "was", "we", "were", "what", "when", "where", "which", "while", "who", "whom", "why", "with", "would",
        "you", "your", "yours", "yourself", "yourselves", "tell",
        # Domain-specific stopwords
        "patient", "clinical", "summary", "trend", "comment", "attached", "image", "audio", "please",
        "systolic", "diastolic", "blood", "pressure", "reading", "readings", "date", "value", "mmhg", "latest",
        "write", "given", "findings", "describe", "summarize", "present", "chart", "data"
    }

    # Convert the entire prompt to lowercase first
    processed_prompt = prompt.lower()
    # Remove punctuation
    processed_prompt = processed_prompt.translate(str.maketrans('', '', string.punctuation))
    words = processed_prompt.split()

    # Filter words
    filtered = [
        w for w in words
        if w not in stop_words and len(w) > 2 and not w.isdigit() and w.isalpha()
    ]

    # If keywords were found, join them. Otherwise, return the original prompt (now in lowercase).
    if filtered:
        return " AND ".join(filtered)
    else:
        # Return the original prompt, but in lowercase for consistency
        return prompt.lower()