# Computer Security Final Project
## Topic 3: Intelligent Anti-Malware Software
### Requirements
1. Extract useful and meaningful features (WIN API calls, n-gram binaries, op instructions, etc.) from given PE files
  * Given a binary file, write a program to determine if it is a PE file, check if it begins with the magic word “MZ” followed by a DOS stub and has “PE” signature in the PE file header, check if the binary is 32- or 64- bit.
     * [Using a hex editor to check bitness of a PE file](https://www.gdatasoftware.com/blog/pebitnesstrick)
     * [How to check if a binary is 32 or 64 bit on Windows](https://superuser.com/questions/358434/how-to-check-if-a-binary-is-32-or-64-bit-on-windows)
  * Given a PE file, write a program code to extract its features
     * [Import Address Table Hooking Tutorial](https://guidedhacking.com/threads/iat-hook-import-address-table-hooking-explained.4244/)
3. Develop an ML algorithm to train model based on selected feature set(s). Then test it on the testing set
4. Implement a GUI tool for users to scan uploaded PE files. Program should conduct the predictions in the backend and display detection results (benign vs. malicious)

### Submissions
* Working code with GUI
* Report containing feature detection method, training/detection alg, and experimental results
* In class demo that shows detection of any executables in a format of PE 

### Resources
* Class Lectures 16-18
* [sklearn decision trees tutorial](https://scikit-learn.org/stable/modules/tree.html)
