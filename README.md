# Gold Insights

#### Video Demo: <https://youtu.be/1mkW7FP0bAQ>
#### Description:

## Introduction
Gold is one of the most important assets in the global financial market, commonly used as a hedge against inflation and economic instability. However, the gold market is highly volatile and influenced by multiple dynamic factors such as inflation rates, geopolitical events, and currency fluctuations. Investors often struggle to predict price movements accurately, and traditional analysis methods fail to capture real-time dynamics.  

Our project **Gold Insights** aims to provide a smart forecasting and analysis platform that predicts gold prices using deep learning models. In addition to accurate forecasting, the system provides educational resources, expert insights, and real-time news, empowering users to make better investment decisions.

---

## Problem Statement
Gold investors face difficulties making informed decisions due to the constant volatility of gold prices. Prices are affected by multiple economic and political factors, making prediction even harder. This project was developed to create a reliable forecasting and analysis system to help users:  
- Predict gold price movements using advanced machine learning models.  
- Analyze historical data along with economic indicators.  
- Stay updated with real-time news and expert recommendations.  

---

## Features
- **Deep Learning Forecasting**: Predict gold prices using LSTM models.  
- **Gold Market Analysis**: Historical and real-time data analysis with interactive charts.  
- **Real-Time News**: Integrated APIs to fetch the latest gold market updates.  
- **Educational Resources**: Provide guidance for beginners to understand gold trading and investment.  
- **Expert Insights**: Recommendations from analysts combined with model predictions.  
- **User-Friendly Website**: Clean and modern UI designed with React for a smooth user experience.  

---

## Tools and Technologies
- **AI & Deep Learning**: Python, LSTM (Keras, TensorFlow)  
- **Front-End**: HTML, CSS, JavaScript, React.js  
- **Back-End**: Node.js, Flask, MongoDB  
- **APIs & Web Scraping**: Yahoo Finance, FRED API, BeautifulSoup, Postman  
- **Visualization**: Recharts, PapaParse, date-fns, Matplotlib, Seaborn  

---

## Objectives
1. Build a deep learning model to predict gold prices using historical and economic data.  
2. Provide buy/sell/hold recommendations based on predicted trends.  
3. Analyze historical data to study the impact of major global events.  
4. Provide an educational section about gold trading and investment.  
5. Integrate APIs for real-time gold prices and news updates.  
6. Develop an easy-to-use website with a clear and responsive UI.  

---

## Approach

### Data Collection and Preprocessing
- Collected gold data from Yahoo Finance using web scraping.  
- Cleaned and normalized the dataset, handling missing values and ensuring consistent time frequency.  
- Combined multiple datasets (gold, oil, dollar index, inflation) into one master DataFrame.  

### Data Analysis
- Explored relationships between gold prices and other indicators.  
- Created visualizations (heatmaps, time series, correlation charts).  
- Highlighted impacts of global events on price fluctuations.  

### Model Development
- Built an **LSTM neural network** using Keras and TensorFlow.  
- Applied **MinMaxScaler** normalization, TimeSeriesSplit validation, and callbacks (early stopping, learning rate reduction).  
- Achieved high performance with:  
  - **R² Score**: 97.01%  
  - **MAPE**: 1.42%  
  - **MAE**: 29.12  
  - **RMSE**: 40.67  

### Front-End
- Designed with **React.js** for responsiveness and ease of use.  
- Used **Recharts** for interactive graphs, **PapaParse** for CSV parsing, and **date-fns** for date manipulation.  
- Implemented dynamic charts, filters, and tooltips to enhance analysis.  

### Back-End
- Built using **Node.js** with MongoDB for data storage.  
- Developed APIs to connect with the prediction model (running on Flask).  
- Added secure login and authentication features.  
- Used Postman for testing and validation.  

---

## Future Work
- Expand predictions to cover other assets such as platinum and cryptocurrencies.  
- Create a personalized recommendation system considering user risk profiles.  
- Develop a mobile app for real-time notifications and easy access.  
- Add community features like discussion forums and user feedback.  

---

## Conclusion
The **Gold Insights** project successfully developed a platform that combines **deep learning forecasting**, **real-time analysis**, and **educational resources** into a single user-friendly system.  

Key achievements include:  
- A responsive website built with React for interactive gold market analysis.  
- A robust back-end with Node.js and MongoDB for secure user management.  
- A deep learning LSTM model achieving strong predictive accuracy.  
- Integration of APIs for real-time gold prices and market news.  

This project provides valuable insights and tools to support investors in making informed, data-driven decisions while learning more about the dynamics of the gold market.  

---

## References
- [Bloomberg](https://www.bloomberg.com)  
- [Gold Predictor](https://goldpredictor.com)  
- [TradingView](https://www.tradingview.com)  
- [FRED API](https://fred.stlouisfed.org/docs/api/fred/)  
- [Yahoo Finance](https://finance.yahoo.com)  
