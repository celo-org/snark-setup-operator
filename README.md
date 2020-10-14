# SNARK setup operator

The operator is responsible for monitoring and verifying the operation of the coordinator.

Tools included:
* `monitor` - checks the status of the setup:
  * Did any participants time out?
  * Did all chunks finish?
  * What are the incomplete chunks?
  
* `verify_transcript` - given a coordinator state and participant IDs, verifies the entire setup as run by the coordinator:
  * Verify each contribution in each chunks, including signatures and the hash chain.
  * Combine and apply the beacon.
  * Verify ratios hold.
  