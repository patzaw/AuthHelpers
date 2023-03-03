library(AuthHelpers)

###############################################################################@
## Azure AD authentication ----

## Get the initial credentials
device_credentials <- create_azure_device_credentials(
   resource=c("api://kmt-prd01/user_impersonation"),
   tenant="237582ad-3eab-4d44-8688-06ca9f2e613b",
   app="f55d2b52-9fed-4b05-8b0a-b24cf8149922"
)

## The following line can be used to update the code if needed
# device_credentials$update_creds()

## Print the user code and go to the verification URL
device_credentials$get_user_code()
device_credentials$browse_verification_uri()

## After authenticating, request the token (default timeout: 15 seconds)
device_credentials$request_token()

## Verify the validity of the token and get it
device_credentials$is_valid()
device_credentials$get_token()
device_credentials$get_access_token()

## The following lines can be used to save the token in a file
# saveRDS(device_credentials, file="~/etc/kmt.rds", compress=FALSE)
# device_credentials <- readRDS("~/etc/kmt.rds")

## The token can be refreshed if not valid anymore
# device_credentials$refresh_token()

###############################################################################@
## Connecting to TKCat with Azure AD token ----

library(TKCat)
k <- chTKCat(
   "tkcat.ucb.com",
   password="",
   port=443, https=TRUE,
   extended_headers=list(
      "Authorization"=paste("Bearer", device_credentials$get_access_token())
   )
)

###############################################################################@
## Connecting to a neo4j database with Azure AD token ----
library(neo2R)
graph <- startGraph(
   "https://dodo.ucb.com:",
   .opts = list(
      extendedHeaders=list(
         "Authorization"=paste("Bearer", device_credentials$get_access_token())
      )
   )
)

###############################################################################@
## Connecting to BED with Azure AD token ----
library(BED)
connectToBed(
   "https://bed.ucb.com",
   remember=FALSE, useCache=TRUE,
   .opts = list(
      extendedHeaders=list(
         "Authorization"=paste("Bearer", device_credentials$get_access_token())
      )
   )
)


