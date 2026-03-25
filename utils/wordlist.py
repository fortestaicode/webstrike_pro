"""
Wordlist - Wordlist management utilities
"""
import random
from pathlib import Path
from typing import List, Optional

class WordlistManager:
    def __init__(self, wordlist_dir: str = "wordlists"):
        self.wordlist_dir = Path(wordlist_dir)
        self.wordlist_dir.mkdir(exist_ok=True)
    
    def load(self, name: str) -> List[str]:
        """Load wordlist by name"""
        filepath = self.wordlist_dir / f"{name}.txt"
        
        if not filepath.exists():
            return []
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    
    def save(self, name: str, words: List[str]):
        """Save wordlist"""
        filepath = self.wordlist_dir / f"{name}.txt"
        
        with open(filepath, 'w', encoding='utf-8') as f:
            for word in words:
                f.write(f"{word}\n")
    
    def generate_variations(self, base_words: List[str], 
                           extensions: List[str] = None) -> List[str]:
        """Generate word variations"""
        variations = []
        
        for word in base_words:
            variations.append(word)
            variations.append(word.lower())
            variations.append(word.upper())
            variations.append(word.capitalize())
            
            if extensions:
                for ext in extensions:
                    variations.append(f"{word}{ext}")
                    variations.append(f"{word}.{ext}")
        
        return list(set(variations))
    
    def shuffle(self, words: List[str]) -> List[str]:
        """Shuffle wordlist"""
        shuffled = words.copy()
        random.shuffle(shuffled)
        return shuffled