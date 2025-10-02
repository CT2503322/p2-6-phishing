import pandas as pd
import os
import joblib
import random

from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB, ComplementNB
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sklearn.tree import DecisionTreeClassifier

"""
Loads data depending on what is needed
"""

# Loads Enron dataset (Can be removed since not used, kept just in case)
def load_enron():
    data = pd.read_json("enron_emails_extracted.json")
    print(data)
    return data

# Loads the Kaggle training data, sorted into ham and spam.
def load_training_data():
    data = []
    base_dir = os.path.join(os.path.dirname(__file__), "..", "data", "combinedlabelled")
    for label in ["ham", "spam"]:
        folder = os.path.join(base_dir, label)
        for filename in os.listdir(folder):
            file_path = os.path.join(folder, filename)
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().split("\n\n", 1)[-1]  # Skips headers, training on just the content so as to reduce noise 
                data.append({"text": content, "label": label})
    return data

# Prepares data for training and testing
def prepare_data_split(data):
    texts = [d["text"] for d in data]
    labels = [d["label"] for d in data]
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )
    return X_train, X_test, y_train, y_test

"""
Training functions
"""

# Trains a Naive Bayes(ComplementNB version) model on data provided. Better for unbalanced data such as the Kaggle dataset
def train_nb_complement(data):
    X_train, X_test, y_train, y_test = prepare_data_split(data)

    clf = make_pipeline(
        TfidfVectorizer(ngram_range=(1,2), min_df=2),
        ComplementNB()
    )

    clf.fit(X_train, y_train)
    return clf

# Trains a Naive Bayes(MultinomialNB version) model on data provided. Better for balanced data, hence the limit of legit vs phishing emails have been perfectly balanced. As all things should be.
def train_nb_multinomial(data):
    ham_samples = [d for d in data if d["label"] == "ham"]
    spam_samples = [d for d in data if d["label"] == "spam"]
    if len(ham_samples) > 1396:
        ham_samples = random.sample(ham_samples, 1396)
    data_balanced = ham_samples + spam_samples

    X_train, X_test, y_train, y_test = prepare_data_split(data_balanced)

    clf = make_pipeline(
        TfidfVectorizer(ngram_range=(1,2), min_df=2),
        MultinomialNB()
    )

    clf.fit(X_train, y_train)
    return clf

# Trains a Logistic Regression model on data provided. An alternative to Naive Bayes models
def train_logistic_regression(data):
    X_train, X_test, y_train, y_test = prepare_data_split(data)

    clf = make_pipeline(
        TfidfVectorizer(ngram_range=(1,2), min_df=2),
        LogisticRegression(max_iter=1000)
    )

    clf.fit(X_train, y_train)
    return clf

# Trains Decision Tree model on data provided.
def train_decision_tree(data):
    X_train, X_test, y_train, y_test = prepare_data_split(data)

    clf = make_pipeline(
        TfidfVectorizer(ngram_range=(1, 1), min_df=5),
        DecisionTreeClassifier(
            random_state=42, 
            max_depth=10, 
            min_samples_split=5, 
            min_samples_leaf=5, 
            class_weight='balanced'
        )
    )

    clf.fit(X_train, y_train)
    return clf

"""
Model persistence functions
"""

def save_model(model, model_name):
    model_dir = os.path.join(os.path.dirname(__file__), "..", "models")
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, f"{model_name}.pkl")
    joblib.dump(model, model_path)
    return model_path

def load_model(model_name):
    model_path = os.path.join(os.path.dirname(__file__), "..", "models", f"{model_name}.pkl")
    if os.path.exists(model_path):
        return joblib.load(model_path)
    return None

"""
Testing function
"""
# Tests accuracy of models on provided test data. Can test any of the above models. 
def test_model_accuracy(clf, X_test, y_test):
    y_pred = clf.predict(X_test)
    print(f"Accuracy: {clf.score(X_test, y_test)*100:.2f}%")
    print(classification_report(y_test, y_pred))

"""
Model-agnostic prediction function
"""
# Inputs the text from the user, then the model it is supposed to use, then returns the prediction and probability
def predict_phishing(text, model):
    proba = model.predict_proba([text])[0]
    classes = model.classes_.tolist()
    label = model.predict([text])[0]
    prob = proba[classes.index(label)]
    label_str = "Phishing" if label == "spam" else "Legitimate"
    return {"label": label_str, "percent": f"{prob*100:.2f}"}

if __name__ == "__main__":
    # read enron emails (legacy, not used)
    # load_enron("enron_emails_extracted.json")

    # load training data from Kaggle dataset
    datatest = load_training_data()

    # Trains all the models for comparison, but takes some time though, recommended to just import the models required from here instead.
    nbc_model = train_nb_complement(datatest)
    nbm_model = train_nb_multinomial(datatest)
    lr_model = train_logistic_regression(datatest)
    dt_model = train_decision_tree(datatest)

    # Save the models
    save_model(nbc_model, "naivebayes_complement")
    save_model(nbm_model, "naivebayes_multinomial")
    save_model(lr_model, "logistic_regression")
    save_model(dt_model, "decision_tree")

    """
    Basic test case for prediction function, prints out the results of all 3 models for comparison.
    """

    output_nbc = predict_phishing("Congratulations! You've won a lottery of $1,000,000. Click here to claim your prize.", nbc_model)
    output_nbm = predict_phishing("Congratulations! You've won a lottery of $1,000,000. Click here to claim your prize.", nbm_model)
    output_lr = predict_phishing("Congratulations! You've won a lottery of $1,000,000. Click here to claim your prize.", lr_model)
    output_dt = predict_phishing("Congratulations! You've won a lottery of $1,000,000. Click here to claim your prize.", dt_model)

    print(f"Naive Bayes (ComplementNB): {output_nbc['label']}, {output_nbc['percent']}% \nNaive Bayes (MultinomialNB): {output_nbm['label']}, {output_nbm['percent']}% \nLogistic Regression: {output_lr['label']}, {output_lr['percent']}% \nDecision Tree: {output_dt['label']}, {output_dt['percent']}%")
