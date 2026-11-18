import json


class PhishingPredictorV6:

    def __init__(self, model_path):
        with open(model_path, "r", encoding="utf-8") as file:
            self.model = json.load(file)

        self.feature_names = self.model["feature_names"]
        self.classes = self.model["classes"]
        self.trees = self.model["trees"]

        if len(self.feature_names) != 37:
            raise ValueError("Invalid V6 feature count.")

        if len(self.trees) != 200:
            raise ValueError("Invalid V6 tree count.")

    def predict_tree(self, tree, features):

        node = 0

        while tree["children_left"][node] != -1:

            feature_index = tree["feature"][node]
            threshold = tree["threshold"][node]

            if features[feature_index] <= threshold:
                node = tree["children_left"][node]
            else:
                node = tree["children_right"][node]

        return tree["value"][node]

    def predict_proba(self, feature_dict):

        features = [
            float(feature_dict[name])
            for name in self.feature_names
        ]

        class_totals = [0.0] * len(self.classes)

        for tree in self.trees:

            values = self.predict_tree(tree, features)
            total = sum(values)

            if total > 0:
                for index, value in enumerate(values):
                    class_totals[index] += value / total

        probabilities = [
            value / len(self.trees)
            for value in class_totals
        ]

        return probabilities

    def predict(self, feature_dict):

        probabilities = self.predict_proba(feature_dict)

        return self.classes[
            probabilities.index(max(probabilities))
        ]