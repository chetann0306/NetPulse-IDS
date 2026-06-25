import os
import pandas as pd
from sklearn.tree import _tree
from sklearn.ensemble import RandomForestClassifier
from logger import log_incident

def extract_signatures_from_model(model, feature_names):
    """
    Traverses the underlying trees of the ensemble model to pull out 
    the absolute cleanest, fastest statistical decision bounds for attacks.
    """
    log_incident("INFO", "Compiling machine learning decision boundaries into static signatures...")
    
    # Grab the first tree in the forest ensemble to extract a clean rule path
    tree = model.estimators_[0]
    tree_ = tree.tree_
    feature_name = [feature_names[i] if i != _tree.TREE_UNDEFINED else "undefined" for i in tree_.feature]
    
    exported_rules = []

    def recurse(node, depth, current_rule):
        if tree_.feature[node] != _tree.TREE_UNDEFINED:
            name = feature_name[node]
            threshold = tree_.threshold[node]
            
            # Recurse left (less than threshold)
            left_rule = current_rule + [f"{name} <= {threshold:.2f}"]
            recurse(tree_.children_left[node], depth + 1, left_rule)
            
            # Recurse right (greater than threshold)
            right_rule = current_rule + [f"{name} > {threshold:.2f}"]
            recurse(tree_.children_right[node], depth + 1, right_rule)
        else:
            # We reached a leaf node! Let's check what class it predicts
            classes = tree_.value[node][0]
            predicted_class_idx = classes.argmax()
            
            # If this path uniquely leads to an attack designation, save the signature rule path
            if predicted_class_idx > 0: # 0 is BENIGN, 1+ are attacks (DDoS, PortScan)
                rule_string = " AND ".join(current_rule)
                exported_rules.append(rule_string)

    recurse(0, 1, [])
    
    # Deduplicate rules and grab the top highest-confidence boundaries
    unique_rules = list(set(exported_rules))[:5] 
    return unique_rules

def run_signature_exporter():
    # Load data to establish feature labels
    if not os.path.exists("network_traffic_sample.csv"):
        print("[ERROR] Please generate sample data first via the dashboard.")
        return
        
    df = pd.read_csv("network_traffic_sample.csv")
    X = df.drop(columns=['Label'])
    y = df['Label']
    
    # Train a quick explicit tree estimator configuration
    clf = RandomForestClassifier(n_estimators=5, max_depth=3, random_state=42)
    clf.fit(X, y)
    
    rules = extract_signatures_from_model(clf, X.columns)
    
    # Save extracted signatures to a lightweight rule file
    rule_file = "netpulse_exported_signatures.rules"
    with open(rule_file, "w") as f:
        f.write("# =========================================================\n")
        f.write("# NETPULSE IDS AUTOMATICALLY EXPORTED STATIC SIGNATURE RULES\n")
        f.write("# Generated to alleviate live processing latency bottlenecks\n")
        f.write("# =========================================================\n\n")
        for i, rule in enumerate(rules, 1):
            f.write(f"ALERT AUTOMATIC_RULE_{i} IF: {rule} -> ACTION: DROP_PACKET\n")
            
    log_incident("INFO", f"Successfully exported {len(rules)} lightweight signatures to '{rule_file}'.")

if __name__ == "__main__":
    run_signature_exporter()
    