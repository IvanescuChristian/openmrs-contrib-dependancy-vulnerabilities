The app is supposed to have the following logic:
1. Extract Data through github api with a local fallback.
2. The Data is extracted directly from the expected module-billing module-idgen and core respectively.
3. If Data isn`t found, it shall be searched throughout the entire zipArchive( any .json file).
4. Now we can assume Data exists though not guaranteed to fill all fields.
5. Each module has its own section and can be opened as such.
6. Each module now has a Dependency, Version, Severity,CVEs, Exploit, Fix Version field.
7. All fields can be sorted in a priorityQueue to be able to MultiSort, Queue which will have small (n) next to each field selected(where n is a number = 0..) .
8. Now each dependency can pe opened Displaying all CVEs . To be able to expand upon this and add all require fields, a python selenium extraction tool would be recommended( can be done in a few hours) .
9. Again field can be selected and sorted.The CVEs are headers linked to a link ( similar to SymLinks for Linux enthusiasts) .
10. Final product should be completely scaled to the dimension of each user and have no issue.
11. The Github Api of course is hidden in a .env and inaccessible to the public(also blurred in the display(can`t be copy pasted,sorry:) ) .




VeryFriendlySolver