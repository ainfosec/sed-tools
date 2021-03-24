#ifndef PASSWORD_H
#define PASSWORD_H

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <termios.h>
#include <inttypes.h>
#include <stdio.h>

#define ON 1
#define OFF 0
#define TRUE 1
#define FALSE 0
#define ATTEMPTS_ALLOWED 3

#define CURRENT_COMPLEXITY_CONFIGURATION   "Current Password Complexity Configuration"
#define MIN_CHARS                          "Minimum Number of Characters: "
#define MAX_CHARS                          "Maximum Number of Characters: "
#define MIN_UPPER                          "Minimum Number of UpperCase Characters: "
#define MIN_NUMBERS                        "Minimum Number of Numeric Characters: "
#define MIN_SPECIAL                        "Minimum Number of Special Characters: "
#define MAX_SEQUENCE                       "Maximum Number of Sequence Characters: "
#define NEW_COMPLEXITY_CONFIGURATION       "New Password Complexity Configuration"
#define KEEP_MOIDFY_CONFIGURATION          "Press K to keep the current configuration, or  M to modify it."
#define COMPLEXITY_ERROR                   "Error: Could not configure Password Requirements"

struct password_complexity 
{
    int32_t maxNumberOfChars;    /**< Holds the maximum number of characters that the password can be */
    int32_t minNumberOfChars;    /**< Holds the minimum number of characters that the password can be */
    int32_t numberOfCaps;        /**< Holds the minimum number of uppercase characters that the password requires */
    int32_t numberOfSpecial;     /**< Holds the minimum number of special characters the the password requires */
    int32_t numberofNumbers;     /**< Holds the minimum number of numeric characters that the password can hold */
    int32_t maxSequenceChars;    /**< Holds the maximum number of consecutive characters allowed */
};

/*
    @description: Turns terminal echoing on or off. 

    @parameter enable - Turns on terminal echo when set to 1, or turns off
                        echo when set to 0
*/
void toggleTerminalEcho(char enable);

/*
    @description: Reads in at most bufferLenghth bytes from the user, and store the results in buffer

    @parameter buffer - The buffer to store the string
    @parameter bufferLength - The size of the buffer. If NULL termination is desired, pass in an extra byte, i.e length + 1

    @return - The buffer filled with the string on success, NULL on error
*/
char *readInput(char *buffer, int bufferLength);

/* 
    @description: Prompts the user for a password with echoing automatically disabled

    @parameter username    - Message to prompt with
    @paramter buffer       - The buffer to store the password in
    @paramter bufferLength - The length of the buffer. If NULL termination is desired, pass in an extra byte, i.e length + 1
*/    
char *promptPassword(char *prompt, char *buffer, int bufferLength);

/*
    @description: Allows the user to set a password. The password gets verified to prevent mistyping. The password can also be 
                  verified against a complexty set that it must meet.

    @parameter prompt            - Message to prompt with
    @parameter passBuffer        - The buffer to store the password in
    @parameter passBufferLength  - The length of the password buffer
    @parameter complexity        - A pointer to the complexity struct that the password must abide by. NULL if no complexity.
    @parameter retryLimit        - The number of attempts that the user gets to enter their password.

    @return - The password that was set by the user. NULL if error.
*/
char *setPassword(char *prompt, char *passBuffer, int passBufferLength, struct password_complexity *complexity, int retryLimit);

/*
    @description: Verifies that a password meets the requirements of the set password complexity

    @parameter complexity - The complexity that is set for the password
    @parameter password   - The password to verify

    @return - 0 on Success, 1 on error   
*/
int verifyComplexity(struct password_complexity *complexity, char *password);

/*
    @description: An interactive way for the user to set the password complexity

    @parameter complexity - Pointer to the password_complexity struct to be set.

    @return - 0 on success, 1 on failure
*/
uint32_t setComplexity(struct password_complexity *complexity);


/*
    @description: Checks to make sure that the password meets the maxSequence set

    @parameter password - The password to check

    @parameter maxSequence - The maximum number of consecutive characters allowed.

    @return - 0 on success, 1 on failure
*/
int checkSequence(char *password, int maxSequence);

const char *getCompStringError(uint32_t errorNum);
#endif
