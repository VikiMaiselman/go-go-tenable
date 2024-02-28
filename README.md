# PRE-STEPS
- cloned the initial repo, added a new cool_resource/ folder with 2 files: policy.repo and .json
- installed go
- if you clone my repo in order to run engine use: $go run ./cmd/main.go


# EXERCISE 1
- can be seen in the commit "task1"
- used a Rule to create a Set (the conditions that should be true were encryption == false && RiskyWrite)

# EXERCISE 2
- added another Rule, tried to differentiate between 2 situations by using not some_field, but in rego (as in many programming languages) this operator does not differentiate between the falsy state (field == false) and undefined (field missing)
- so created a function that counts the number of key-value pairs in each subobject in json 
- (I admit that the solution is not scalable and a bit hardcoded - if it was a real json I most certainly could not rely on the exact number of key-value pairs expected, but it was the only solution that worked for me at this stage)

# EXERCISE 3
- could not get to the solution
- initially added a Logger, but it could print me the lines of the errors thrown in main.go file itself, not lines of .json file
- also tried with Trace and TraceBuffer, but still did not work
- I suppose I needed to figure out which library should be used and imported in .go file...

# THANK YOU