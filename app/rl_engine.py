import os
import sqlite3
# pyrefly: ignore [missing-import]
import numpy as np

# Global Q-Table
Q_TABLE = {}

def get_binned_features(url):
    """
    Extracts features from the URL and applies binning.
    Binning reduces the state space, allowing the RL agent to generalize 
    to unseen URLs more effectively instead of requiring exact matches.
    """
    url = url.lower().replace(' ', '')
    length_bin = min(len(url) // 10, 10)  # 0 to 10
    dots_bin = min(url.count('.'), 5)     # 0 to 5
    has_at = 1 if '@' in url else 0       # 0 or 1
    dash_bin = min(url.count('-'), 5)     # 0 to 5
    has_https = 1 if 'https' in url else 0 # 0 or 1
    
    return (length_bin, dots_bin, has_at, dash_bin, has_https)

def train_rl_agent(db_path='phishing_db.sqlite'):
    """
    Trains the Q-Learning agent on startup using data from SQLite.
    If the DB or training data doesn't exist, it skips gracefully.
    """
    global Q_TABLE
    if not os.path.exists(db_path):
        print(f"[RL Core] Training skipped: Database {db_path} not found.")
        return
        
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if training table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='phishing_urls'")
        if not cursor.fetchone():
            print("[RL Core] Training skipped: 'phishing_urls' table not found.")
            conn.close()
            return
            
        cursor.execute("SELECT url, risk_score FROM phishing_urls")
        data = cursor.fetchall()
        conn.close()
        
        if not data:
            print("[RL Core] Training skipped: No data in 'phishing_urls'.")
            return
            
        # RL Hyperparameters
        alpha = 0.1   # Learning rate
        gamma = 0.9   # Discount factor
        epsilon = 0.1 # Exploration rate
        n_episodes = 50 # Simulate learning over the dataset multiple times
        
        print(f"[RL Core] Initializing Neural Training on {len(data)} records...")
        
        for _ in range(n_episodes):
            for row in data:
                url, risk_score = row
                state = get_binned_features(url)
                
                # Ground truth from DB
                actual_risk = 1 if risk_score > 50 else 0
                
                if state not in Q_TABLE:
                    Q_TABLE[state] = [0.0, 0.0]
                    
                # Epsilon-greedy selection
                if np.random.uniform(0, 1) < epsilon:
                    action = np.random.choice([0, 1])
                else:
                    action = np.argmax(Q_TABLE[state])
                
                # Calculate Reward
                reward = 1 if action == actual_risk else -1
                
                # Q-Learning Update Rule (Contextual Bandit style as episodes are 1-step)
                old_value = Q_TABLE[state][action]
                Q_TABLE[state][action] = old_value + alpha * (reward - old_value)
                
        print(f"[RL Core] Training complete. Q-Table learned {len(Q_TABLE)} unique states.")
        
    except Exception as e:
        print(f"[RL Core] Error during RL training: {e}")

def predict_rl_score(url):
    """
    Predicts the risk score of a URL using the trained Q-Table.
    Returns:
        score (int): 0 to 100
        confidence (str): 'high' or 'low'
    """
    global Q_TABLE
    state = get_binned_features(url)
    
    if state not in Q_TABLE:
        # Unseen state: return neutral 50 with low confidence
        return 50, "low"
        
    q_values = Q_TABLE[state]
    action = np.argmax(q_values)
    
    safe_q, risk_q = q_values
    
    # Calculate score based on Q-value difference (confidence mapping)
    if action == 1:
        # Predicts Risky (Score 50-100)
        conf = min(max(risk_q - safe_q, 0.1), 1.0)
        score = int(50 + (conf * 50))
        return score, "high"
    else:
        # Predicts Safe (Score 0-50)
        conf = min(max(safe_q - risk_q, 0.1), 1.0)
        score = int(50 - (conf * 50))
        return score, "high"
