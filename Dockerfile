# Use a lightweight Python image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Set environment variables
# These can be overridden at runtime
ENV OPENAI_API_KEY=your_openai_api_key
ENV TAVILY_API_KEY=your_tavily_api_key
ENV LANGCHAIN_API_KEY=your_langchain_api_key

# Expose the port if your application runs on a specific port
# EXPOSE 8000

# Command to run the application
CMD ["python", "main.py"]
