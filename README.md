# PhishingDetection
31261 Internetworking Project - Developing a Machine Learning (ML) based Phishing Detection System
Group members:
1. Olivia Lim - 24677078
2. Maximus Kay Garcia - 14445478
3. Chika Sugianto - 24583231
4. Quang Minh Nguyen - 14415297

# Purpose
This detection system is developed to detect and distinguish between the suspicious (phishing URL) and legitimate ones. Within this detection system, the group has implemented the Random Forest classfication for the ML part. Moreover, the accuracy for this detection system is 0.9521.

# Modules 
In the "create_datasets.py", 
1. Pandas module for the data manipulation
2. Requests for sending the HTTP request and fetch the data from PhisTank and Tranco
3. PhisTank website to fetch all phishing URL data
4. Tranco website to fetch all legitimate URL data
5. IO (StringIO) for making the string data to be compatible for Pandas mmodule

In the "phishing_detection.py", 
1. Pandas module for data manipulation
2. Numpy module for the numerical operations
3. Re module for regular expression operations
4. Math module for mathematical functions
5. Matplotlib.pyplot module for plotting charts and graphs
6. Seaborn module for statistical data visiualisation (part of Matpotlib)
7. Sckit-learn module for the Machine Learning with Random Forest Classifier 

# How to Run the Code 
1. It is important to ensure that Python has been installed in your laptop
2. Install all required modules to the laptop through Command Line
3. Run the "create_datasets.py" to obtain the saved datasets file
4. Once the "url_dataset.csv" created, run the "phishing_detection.py" to start train the model and test some URLs. 

# Results 
The accuracy = 0.9521
The results can be seen from the terminal and data visualisation. The followings are the visualistion results after running this code. 
1. Confusion Matrix Heatmap
<img width="604" alt="Confusion Matrix Heatmap" src="https://github.com/user-attachments/assets/46a70f23-8d12-49e7-b7eb-7f5ed0e87283" />

2. Feature Importance Statistic
<img width="799" alt="Future Importance Statistic" src="https://github.com/user-attachments/assets/1fd7d965-3916-4d76-b87d-311697875e9c" />

3. Pie Chart of Phishing Detection Results
<img width="505" alt="Pie Chart of Phishing Detection Result " src="https://github.com/user-attachments/assets/66a9abc1-e53b-4ea3-a7bd-4b98d6613b8b" />

# Thank You!
Please feel free to reach out if you have some questions regarding this project :)
