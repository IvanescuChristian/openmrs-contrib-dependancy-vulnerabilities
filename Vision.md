The version I am sending will take the data from the given repo/data.If there is no data it will search locally.
I have another version that looks first for a zip in dashboard/public and extracts the zip then uses the jsons. If there is no zip it looks for the json files inside dashboard/data still through an api key.If no data is found it will look in the same places locally.
I propose a version that will be fed the repositories where one would like to look then the app searches the repositories for the json files through a github api .

