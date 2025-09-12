# Guide to Download Enron Dataset

## Overview
The Enron dataset is a large collection of emails (approximately 500,000 emails) from the Enron email scandal. To avoid adding these files to your Git repository, download them to the `enron_dataset` folder, which is already configured to be ignored in `.gitignore`.

## Steps to Download

1. **Create the target directory:**
   ```
   mkdir -p enron_dataset
   cd enron_dataset
   ```

2. **Download the dataset:**
   Use `wget` or `curl` to download the dataset. The dataset is available as a compressed tar.gz file.

   Option 1 - Using wget:
   ```
   wget https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz
   ```

   Option 2 - Using curl:
   ```
   curl -O https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz
   ```

   Note: These commands should be run from within the `enron_dataset` directory.

3. **Extract the dataset:**
   Once downloaded, extract the contents:
   ```
   tar -xzf enron_mail_20150507.tar.gz
   ```

4. **Optional: Clean up:**
   After extraction, you can remove the downloaded archive to save space:
   ```
   rm enron_mail_20150507.tar.gz
   ```

## Expected Structure
After extraction, the `enron_dataset` folder should contain:
- A `maildir` directory with subfolders containing `.eml` files
- Various Enron employee mailboxes organized hierarchically

## Notes
- The dataset is large (around 1-2 GB compressed), so ensure you have sufficient disk space
- File operations may take several minutes due to the large number of files
- All files in `enron_dataset` are ignored by Git, so they won't be committed to your repository
