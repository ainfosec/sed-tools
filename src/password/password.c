#include "../include/password/password.h"
#include "../include/sed/error.h"


void toggleTerminalEcho(char enable)
{
    struct termios nflags;
    
    tcgetattr(fileno(stdin),&nflags);
    
    if(enable)
    {
        nflags.c_lflag |= ECHO;
    }
    else
    {
        nflags.c_lflag &= ~ECHO;
        nflags.c_lflag |= ECHONL;
    }
    
    if(tcsetattr(fileno(stdin), TCSANOW, &nflags))
    {
        printf("Warning could not toggle termincal echo state!\n");
    }
}

char *readInput(char *buffer, int bufferLength)
{
    char tempBuffer[bufferLength + 2];

    // Make sure everything is empty, dont trust the sender
    memset(tempBuffer, 0, bufferLength + 2);
    memset(buffer, 0, bufferLength);
    
    /* Prevent the user from thinking they created a password that is greater than bufferlength */
    if (fgets(tempBuffer, bufferLength + 2, stdin) == NULL)
    {   
        sedError = EBADINPUT;
        return NULL;
    }

    /* Erase the trailing newline character from the string that fgets put there */
    if (tempBuffer[strlen(tempBuffer) - 1] == '\n')
        tempBuffer[strlen(tempBuffer) - 1] = '\0';
    
    /* We can now check to see if the user entered more than what was allowed */
    if (strlen(tempBuffer) > bufferLength)
    {   
        sedError = ESTRINGMAX;
        return NULL;
    }

    strncpy(buffer, tempBuffer, bufferLength);

    /* Clear password/string from memory */
    memset(tempBuffer, 0, bufferLength + 2);
    
    return buffer;
}


char *promptPassword(char *prompt, char *buffer, int bufferLength)
{
    
    // Don't rely on the user to pass in an empty buffer
    memset(buffer, 0, bufferLength);
    
    // Prompt. Maybe pass this in as a parameter? like char *prompt, instead of username?
    printf("%s", prompt);
 
    // Echo gets turned off
    toggleTerminalEcho(OFF);

    // The the input from the user while the echo is turned off
    if (readInput(buffer, bufferLength) == NULL)
    {
        return NULL;
    }

    // Enable echoeing again
    toggleTerminalEcho(ON);

    return buffer;
}

char *setPassword(char *prompt, char *passBuffer, int passBufferLength, struct password_complexity *complexity, int retryLimit)
{
    char tempBuffer[passBufferLength], confirmed = 0, i = 1, retVal;

    /* Loop until the user created a password that meets the complexity (if any) and had it verified */
    while (!confirmed)
    {
        retVal = 0;
        
        // Clear it
        memset(passBuffer, 0, passBufferLength);
        memset(tempBuffer, 0, passBufferLength);
                
        printf("%s", prompt);

        // Make sure terminal echo is off
        toggleTerminalEcho(OFF);

        // Get users password
        if (readInput((char *)tempBuffer, passBufferLength) != NULL)
        {
            if (complexity != NULL)
            {
                // User did not meet the complexity requirements
                if ((retVal = verifyComplexity(complexity, (char *)tempBuffer)) == 2)
                {
                    // If 2 was the return value then a faulty struct was detected
                    toggleTerminalEcho(ON);
                    return NULL;
                }                   
            }

            if (!retVal)
            {
                printf("Please re-enter the password: ");

                // Verify the password
                if ((readInput(passBuffer, passBufferLength) != NULL))
                {
                    if ((strlen(passBuffer) == strlen(tempBuffer)) && (!strncmp(tempBuffer, passBuffer, strlen(passBuffer))))
                    {
                        // Make sure terminal echo is on
                        toggleTerminalEcho(ON);
                        confirmed = 1;
                    }

                    else
                    {
                        printf("Passwords do not match!\n");

                        /* Apply a retry limit if the user set one */
                        if (retryLimit)
                        {
                            if (i == retryLimit)
                            {
                                printf("Exceeded Try limit\n");

                                // Make sure terminal echo is on
                                toggleTerminalEcho(ON);
                                return NULL;
                            }        
                            i++;
                        }
                    }
                } 
            }    
        }
    }

    memset(tempBuffer, 0, strlen(tempBuffer));

    return passBuffer;
}

int verifyComplexity(struct password_complexity *complexity, char *password)
{
    unsigned int i, capCount = 0, numCount = 0, specialCount = 0, lowerCount = 0;

    if (complexity == NULL)
    {
        fprintf(stderr, "Error: Invalid complexity\n");
        return sedError = ECOMPR;
    }
    
    // Make sure the struct is actually sanitized
    if (complexity->maxNumberOfChars <= 0 || complexity->minNumberOfChars < 0 || complexity->numberOfCaps < 0 ||
        complexity->numberOfSpecial < 0 || complexity->numberofNumbers < 0)
    {
        fprintf(stderr, "Invalid complexity structure detected. Either one of the members is negative,Max Number of"
                        "characters is equal to 0, or NULL pointer was passed in\n");
        return 2;
    }

    // Check for garbage characters (anything that is not a number/alphabet/special character)
    for (i = 0; i < strlen((char *)password); i++)
    {
        if (password[i] < ' ' || password[i] > '~')
        {
            fprintf(stderr, "Unsupported characters detected in password string\n");
            return 1;
        }
    }

    // verifying minimum 
    if (strlen((char *)password) < complexity->minNumberOfChars)
    {
        printf("Minimum number of characters is not satisfied\n");
        return 1;
    }

    // verifying maximum 
    if (strlen((char *)password) > complexity->maxNumberOfChars)
    {
        printf("Maximum number of characters exceeded\n");
        return 1;
    }

    // Check capitals
    for (i = 0; i < strlen((char *)password); i++)
    {
        if (password[i] >= 'A' && password[i] <= 'Z')
        {
            capCount++;
        }
    }

    if (capCount < complexity->numberOfCaps)
    {
    
        printf("Minimum number of UpperCase characters is not satisfied\n");
        return 1;
    }

    // Check numeric characters
    for (i = 0; i < strlen((char *)password); i++)
    {
        if (password[i] >= '0' && password[i] <= '9')
        {
            numCount++;
        }
    }

    if (numCount < complexity->numberofNumbers)
    {
        printf("Minimum number of numeric characters is not satisfied\n");
        return 1;
    }


    // Check special characters.
    for (i = 0; i < strlen((char *)password); i++)
    {
        if (password[i] >= 'a' && password[i] <= 'z')
        {
            lowerCount++;
        }
    }

    // Check Conesecutive characters
    if (checkSequence(password, complexity->maxSequenceChars))
    {
        fprintf(stderr, "Maximum number of Consecutive characters exceeded\n");
        return 1;
    }


    /* The number of special characters is equal to the length of the password - the number of Uppercase,
       lowercase, and numeric characters */
    specialCount = strlen((char *)password) - (numCount + capCount + lowerCount);

    if (specialCount < complexity->numberOfSpecial)
    {
        printf("Minimum number of special characters is not satisfied\n");
        return 1;
    }

    return 0;
}

uint32_t setComplexity(struct password_complexity *complexity)
{    
    int response, i = 0, values[6];
    char ans[6];
    char *option[6] = {"maximum number of characters", "minimum number of characters", "minimum number of Upper Case letters",
                       "minimum number of special characters", "minimum number of numeric characters", "maximum number of sequence characters"};
    
    // Prompts through each of the complexity components
    while (i != 6)
    {
        memset(ans, 0, 6);
        printf("Enter the %s for the password: ", option[i]);

        if (readInput(ans, 6) == NULL)
            return (sedError = ECOMPW);
        
        response = atoi(ans);

        if (response < 0)
            return (sedError = EICHOICE);
        
        else
            values[i++] = response;  
        
        printf("\n");
    }

    // Set the maximum number of characters
    complexity->maxNumberOfChars = values[0];

    // Set the minimum number of characters     
    complexity->minNumberOfChars = values[1];
        
    // Set the minimum number of Capital letters
    complexity->numberOfCaps = values[2];
   
    // Set the minimum number of Special characters
    complexity->numberOfSpecial = values[3];
   
    // Set the minumum number of numeric characters
    complexity->numberofNumbers = values[4];

    // Set the maximum number of consecutive characters
    complexity->maxSequenceChars = values[5];

    // Checks to see if the number of special, numeric, and Uppercase letters do not exceed the maximum possible characters
    if (((complexity->numberofNumbers) + (complexity->numberOfSpecial) + (complexity->numberOfCaps)) > (complexity->maxNumberOfChars))
    {
        printf("\nThe set of requirements are invalid. The total number of requirements is greater than the maximum number of characters\n");
        return (sedError = ECOMPW);
    }

    return 0;
}

int checkSequence(char *password, int maxSequence)
{
    int i, count = 1;
    char current, prev = 0;

    for (i = 0; i < strlen(password); i++)
    {
        current = password[i];

        if (prev == current)
        {
            count++;

            /* treat a maxSequence number of 0 and 1 the same. Both will mean no repeating characters */
            if (count == maxSequence || maxSequence <= 1)
                return 1;
        }

        else
            count = 1;

        prev = current;
    }

    return 0;
}
