# Email Analysis

## What is Email Analysis

Email analysis is the process of extracting the email header information to expose the email file details. The email header contains the technical details of the email like sender, recipient, path, return address and attachments. Usually, these details are enough to determine if there is something suspicious/abnormal in the email and decide on further actions on the email, like filtering/quarantining or delivering.

There are two main concerns in email analysis.

- Security issues: Identifying suspicious/abnormal/malicious patterns in emails.
- Performance issues: Identifying delivery and delay issues in emails.

We will focus on security concerns on emails, a.k.a. phishing. Phishing emails will usually appear to come from a trusted source, whether that's a person or a business. They include content that tries to tempt or trick people into downloading software, opening attachments, or following links to a bogus website.

## How to Analyse Emails

### Email Header Structure

|Field|Details|
|---|---|
|From|The sender's address.|
|To|The receiver's address, including CC and BCC.|
|Date|Timestamp, when the email was sent.|
|Subject|Te subject of the email.|
|Return Path|The return address of the reply, a.k.a. "Reply-To". If you reply to an email, the reply will go to the address mentioned in this field.|
|Domain Key and DKIM Signatures|Email signatures are provided by email services to identify and authenticate emails.|
|SPF|Shows the server that was used to send the email. It will help to understand if the actual server is used to send the email from a specific domain.|
|Message-ID|Unique ID of the email.|
|MIME-Version|Used MIME version. It will help to understand the delivered "non-text" contents and attachments.|
|X-Headers|The receiver mail providers usually add these fields. Provided info is usually experimental and can be different according to the mail provider.|
|X-Received|Mail servers that the email went through.|
|X-Spam Status|Spam score of the email.|
|X-Mailer|Email client name.|

### Important Email Header Fields for Quick Analysis

Analysing multiple header fields can be confusing at first glance, but starting from the key points will make the analysis process slightly easier. A simple process of email analysis is shown below.

|Questions to Ask / Required Checks|Evaluation|
|---|---|
|Do the "From", "To", and "CC" fields contain valid addresses?|Having invalid addresses is a red flag.|
|Are the "From" and "To" fields the same?|Having the same sender and recipient is a red flag.|
|Are the "From" and "Return-Path" fields the same?|Having different values in these sections is a red flag.|
|Was the email sent from the correct server?|Email should have come from the official mail servers of the sender.|
|Does the "Message-ID" field exist, and is it valid?|Empty and malformed values are red flags.|
|Do the hyperlinks redirect to suspicious/abnormal sites?|Suspicious links and redirections are red flags.|
|Do the attachments consist of or contain malware?|Suspicious attachments are a red flag. File hashes marked as suspicious/malicious by sandboxes are a red flag.|

You'll also need an email header parser tool or configure a text editor to highlight and spot the email header's details easily.

Text editors are helpful in analysis, but there are some tools that can help you to view the email details in a clearer format. For example, `emlAnalyzer` is a tool designed to parse email headers for a better view and analysis process. The tool can show the headers, body, embedded URLs, plaintext and HTML data, and attachments. The sample usage query is explained below.

|Query Details|Explanation|
|---|---|
|emlAnalyzer|Main command|
|-i|File to analyse <br> -i /path-to-file/filename <br> Note: Remember, you can either give a full file path or navigate to the required folder using the "cd" command.|
|--header|Show header|
|-u|Show URLs|
|--text|Show cleartext data|
|--extract-all|Extract all attachments|

Additionally, you can use some Open Source Intelligence (OSINT) tools to check email reputation and enrich the findings. Visit the given site below and do a reputation check on the sender address and the address found in the return path.
Tool: [https://emailrep.io/](https://emailrep.io/)

Here, if you find any suspicious URLs and IP addresses, consider using some OSINT tools for further investigation. While we will focus on using Virustotal and InQuest, having similar and alternative services in the analyst toolbox is worthwhile and advantageous.

|Tool|Purpose|
|---|---|
|VirusTotal|A service that provides a cloud-based detection toolset and sandbox environment.|
|InQuest|A service provides network and file analysis by using threat analytics.|
|IPinfo.io|A service that provides detailed information about an IP address by focusing on geolocation data and service provider.|
|Talos Reputation|An IP reputation check service is provided by Cisco Talos.|
|Urlscan.io|A service that analyses websites by simulating regular user behaviour.|
|Browserling|A browser sandbox is used to test suspicious/malicious links.|
|Wannabrowser|A browser sandbox is used to test suspicious/malicious links.|

After completing the mentioned initial checks, you can continue with body and attachment analysis. Now, let's focus on analysing the email body and attachments. The sample doesn't have URLs, only an attachment. You need to compute the value of the file to conduct file-based reputation checks and further your analysis. As shown below, you can use the `sha256sum` tool/utility to calculate the file's hash value.
Once you get the sum of the file, you can go for further analysis using the `VirusTotal`. Tool: `https://www.virustotal.com/gui/home/upload`.

Now, visit the tool website and use the `SEARCH` option to conduct hash-based file reputation analysis. After receiving the results, you will have multiple sections to discover more about the hash and associated file. Search the hash value, click on the `BEHAVIOR` tab and analyse the details.

After that, continue on reputation check on `InQuest` to enrich the gathered data. Tool: `https://labs.inquest.net/`.

Now visit the tool website and use the `INDICATOR LOOKUP` option to conduct hash-based analysis. Search the hash value, click on the SHA256 hash value highlighted with yellow to view the detailed report and analyse the file details.

After finishing the shown steps, you are finished with the initial email analysis. The next steps are creating a report of findings and informing the team members/manager in the appropriate format.
