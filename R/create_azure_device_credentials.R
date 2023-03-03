#' Create an object for facilitating the management of azure tokens
#'
#' @param resource See the corresponding
#' argument for [AzureAuth::get_azure_token]
#' @param tenant resource See the corresponding
#' argument for [AzureAuth::get_azure_token]
#' @param app resource See the corresponding
#' argument for [AzureAuth::get_azure_token]
#' @param version resource See the corresponding
#' argument for [AzureAuth::get_azure_token] (default: 2)
#' @param offline_access Set to TRUE (default) to allow refreshing the token
#' without authenticating again
#'
#' @return A list with the following functions to manage embedded credentials
#' and token (see examples):
#'
#' - `get_setup()`: get initial azure token setup (params of this function)
#' - `update_creds()`: update the credentials (mainly the user and device codes)
#' - `get_user_code()`: get the user code to paste in the corresponding field
#' at the verification URL
#' - `get_verification_uri()`: get the verification URL where the user code
#' can be pasted
#' - `browse_verification_uri()`: got the verification URL where the user
#' code can be pasted (open a new browser tab or window)
#' - `request_token(timeout=15)`: request the token. It should be called after
#' having pasted the user code at the verification URL and followed the
#' procedure for authenticating there. After a default timeout of 15 seconds,
#' the request is cancelled.
#' - `is_valid()`: Check if the token is valid
#' - `refresh_token(always=FALSE)`: Refresh the token without re-authenticating.
#' If always=FALSE (default), the token is only refreshed if it is not valid
#' anymore.
#' - `get_token()`: Get the full [AzureAuth::AzureTokenDeviceCode] object
#' - `get_access_token()`: Get the access token string
#'
#' @examples
#' \dontrun{
#' ## Get the initial credentials
#' device_credentials <- create_azure_device_credentials(
#'    resource=c("myresource"),
#'    tenant="mytenant",
#'    app="myapp"
#' )
#'
#' ## The following line can be used to update the code if needed
#' # device_credentials$update_creds()
#'
#' ## Print the user code and go to the verification URL
#' device_credentials$get_user_code()
#' device_credentials$browse_verification_uri()
#'
#' ## After authenticating, request the token (default timeout: 15 seconds)
#' device_credentials$request_token()
#'
#' ## Verify the validity of the token and get it
#' device_credentials$is_valid()
#' device_credentials$get_token()
#' device_credentials$get_access_token()
#'
#' ## The following lines can be used to save the token in a file
#' # saveRDS(device_credentials, file="~/etc/mytoken.rds", compress=FALSE)
#' # device_credentials <- readRDS("~/etc/mytoken.rds")
#'
#' ## The token can be refreshed if not valid anymore
#' # device_credentials$refresh_token()
#' }
#'
#' @export
#'
create_azure_device_credentials <- function(
      resource,
      tenant,
      app,
      version=2,
      offline_access=TRUE # use for refreshing token without authenticating
){
   setup=list(
      resource=resource,
      tenant=tenant,
      app=app,
      version=version
   )
   if(offline_access){
      setup$resource <- unique(c(setup$resource, "offline_access"))
   }
   creds <- do.call(AzureAuth::get_device_creds, setup)
   token <- NULL
   devcreds <- list(
      get_setup=function(){
         setup
      },
      update_creds=function(){
         creds <<- do.call(AzureAuth::get_device_creds, setup)
         token <<- NULL
      },
      get_user_code=function(){
         if(is.null(creds)){
            stop(
               "No code available: call update_creds(). ",
               "Note that it will delete the existing token."
            )
         }
         creds$user_code
      },
      get_verification_uri=function(){
         if(is.null(creds)){
            stop(
               "No code available: call update_creds(). ",
               "Note that it will delete the existing token."
            )
         }
         creds$verification_uri
      },
      browse_verification_uri=function(){
         if(is.null(creds)){
            stop(
               "No code available: call update_creds(). ",
               "Note that it will delete the existing token."
            )
         }
         browseURL(creds$verification_uri)
      },
      request_token=function(timeout=15){
         if(AzureAuth::is_azure_token(token)){
            if(token$validate()){
               stop(
                  "A token already exists and is still valid."
               )
            }else{
               stop(
                  "A token already exists but is not valid anymore. ",
                  "You can:\n",
                  "   - refresh the token by calling refresh_token()\n",
                  "   - request a new token by calling ",
                  "update_creds() followed by request_token()"
               )
            }
         }
         tmptoken <- R.utils::withTimeout(
            do.call(
               AzureAuth::get_azure_token,
               c(
                  setup,
                  list(
                     auth_type="device_code",
                     use_cache=FALSE,
                     device_creds=creds
                  )
               )
            ),
            timeout=timeout,
            onTimeout="silent"
         )
         if(!AzureAuth::is_azure_token(tmptoken)){
            stop(
               "Could not retrieve the token in time.",
               "You can try increasing the timeout parameter."
            )
         }
         token <<- tmptoken
         creds <<- NULL
      },
      is_valid=function(){
         if(!AzureAuth::is_azure_token(token)){
            return(FALSE)
         }
         token$validate()
      },
      refresh_token=function(always=FALSE){
         if(!AzureAuth::is_azure_token(token)){
            stop("There is no token: call request_token()")
         }
         if(always || !token$validate()){
            token$refresh()
         }
      },
      get_token=function(){
         if(!AzureAuth::is_azure_token(token)){
            stop("There is no token: call request_token()")
         }
         token
      },
      get_access_token=function(){
         if(!AzureAuth::is_azure_token(token)){
            stop("There is no token: call request_token()")
         }
         token$credentials$access_token
      }
   )
   return(devcreds)
}
