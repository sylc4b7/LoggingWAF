import yfinance as yf
import pandas as pd
import contextlib
from datetime import datetime, timedelta

# List of stock tickers
stocks = ["HSBC", "GOOGL", "V", "MSFT"]  # Add more tickers as needed

def fetch_stock_data(ticker, start_date, end_date):
    # Suppress the console output
    with contextlib.redirect_stdout(None):
        # Fetch historical stock data from Yahoo Finance
        stock_data = yf.download(ticker, start=start_date, end=end_date, progress=False,auto_adjust=False)
    return stock_data

def calculate_happiness_lines(stock_data, window=20):
    # Calculate the mean and standard deviations
    with contextlib.redirect_stdout(None):
        stock_data['Mean'] = stock_data['Close'].rolling(window=window).mean()
        stock_data['StdDev'] = stock_data['Close'].rolling(window=window).std()

        # Calculate the five lines of happiness
        stock_data['Upper Band'] = stock_data['Mean'] + 2 * stock_data['StdDev']  # Mean + 2 StdDev
        stock_data['Lower Band'] = stock_data['Mean'] - 2 * stock_data['StdDev']  # Mean - 2 StdDev

    return stock_data

def main():
    # Calculate the current date and the date 500 days before the current date
    end_date = datetime.now().strftime('%Y-%m-%d')
    start_date = (datetime.now() - timedelta(days=500)).strftime('%Y-%m-%d')

    print("\n\n" + datetime.now().strftime('%Y-%m-%d') + "\n\n")

    # Initialize an empty DataFrame to concatenate results
    concatenated_df = pd.DataFrame()

    for ticker in stocks:
        print(f"Processing data for {ticker}...")

        # Fetch data
        stock_data = fetch_stock_data(ticker, start_date, end_date)

        # Calculate happiness lines with a 20-day rolling window
        result = calculate_happiness_lines(stock_data, window=200)

        # Get the last row of the result
        last_row = result[['Close', 'Mean', 'Upper Band', 'Lower Band']].dropna().tail(1)

        # Convert the last row to an array of values
        last_row_values = last_row.values.flatten()

        # Create a DataFrame from the array of values
        last_row_df = pd.DataFrame([last_row_values], columns=['Close', 'Mean', 'Upper Band', 'Lower Band'])

        # Add the ticker symbol to the DataFrame
        last_row_df.insert(0, 'Ticker', ticker)

        # Concatenate the last row DataFrame to the concatenated DataFrame
        concatenated_df = pd.concat([concatenated_df, last_row_df], ignore_index=True)

    # Print the concatenated DataFrame in a formatted way
    print("\nFinal Stock Data:")
    print(concatenated_df.to_string(index=False))
if __name__ == "__main__":
    main()