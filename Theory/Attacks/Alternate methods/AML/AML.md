# Adversarial machine learning
It manipulates artifical intelligence and machine learning techonology to conduct attack more efficiently.

Consists on adding noise to the input of an AI in order to fool models with deceptive data
![[Pasted image 20231008193005.png]]

## Whitebox attack
Is where the attacker has complete access to the target model, including the model's architecture and its parameters

## Blackbox attack
is a scenario where an attacker has no access to the model and can only observe the outputs of the targeted model

## Poisoning attack
The attacker influences the training data or its labels to cause the model to underperform during deployment. It essentially is contaminating the data.
It specially works with ML as it can be retrained by using data collected during its operation
![[Pasted image 20231008194335.png]]

## Evasion attacks
This are the most prevalent and most researched types of attacks. The attacker mannipulates the data during deployment to deceive previously trained classifiers. 
The attackers attempt to evade detection by obfuscating the content fo malware or spam emails. Therefore, samples are modified to evade detection as the are classified as legitimate without deirectly impacting the training data. Examples of evasion are [[Spoofing attacks]] against biometric verification systems

## Model extraction
Model stealing or model extraction involves an attacker probing a black box machine learning system in order to either reconstruct the model or extract the data it was trained on. This is especially significant when either the training data or the model itself is sensitive and confidential.

# Popular adversarial attack methods
[[Limited-memory BFGS]]
[[FastGradient Sign method]]
[[Jacobian-Based Saliency map attack]]
[[Deepfool attack]]
[[Carlini and Wagner Attack]]
[[Generative adversarial networks]]
[[Zeroth-order optimization attack]]
* Change to acronym when page created

# Resources
https://viso.ai/deep-learning/adversarial-machine-learning/
