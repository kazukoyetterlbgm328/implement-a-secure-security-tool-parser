# 3ov8 Implement a Secure Security Tool Parser

# This Ruby script is designed to parse and analyze security tool output
# for potential vulnerabilities and weaknesses.

# Import necessary libraries
require 'json'
require 'digest'

# Define a class for the security tool parser
class SecurityToolParser
  def initialize(tool_output)
    @tool_output = tool_output
    @vulnerabilities = []
  end

  # Method to parse the tool output and identify vulnerabilities
  def parse_output
    # JSON parse the tool output
    json_output = JSON.parse(@tool_output)

    # Iterate through each finding in the output
    json_output['findings'].each do |finding|
      # Extract relevant information from the finding
      vulnerability = {
        :id => finding['id'],
        :severity => finding['severity'],
        :description => finding['description'],
        :recommendation => finding['recommendation']
      }

      # Calculate a hash of the vulnerability details
      vulnerability[:hash] = Digest::SHA256.hexdigest(vulnerability.to_s)

      # Add the vulnerability to the list
      @vulnerabilities << vulnerability
    end
  end

  # Method to output the identified vulnerabilities
  def output_vulnerabilities
    # Sort the vulnerabilities by severity
    @vulnerabilities.sort_by! { |v| v[:severity] }

    # Output each vulnerability
    @vulnerabilities.each do |vulnerability|
      puts "Vulnerability ID: #{vulnerability[:id]}"
      puts "Severity: #{vulnerability[:severity]}"
      puts "Description: #{vulnerability[:description]}"
      puts "Recommendation: #{vulnerability[:recommendation]}"
      puts "Hash: #{vulnerability[:hash]}"
      puts "------------------------"
    end
  end
end

# Example usage:
tool_output = File.read('security_tool_output.json')
parser = SecurityToolParser.new(tool_output)
parser.parse_output
parser.output_vulnerabilities