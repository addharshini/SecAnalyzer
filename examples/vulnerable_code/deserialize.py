import pickle
def load_user_profile(blob):
    # Insecure deserialization
    return pickle.loads(blob)
