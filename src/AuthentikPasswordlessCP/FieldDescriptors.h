// FieldDescriptors.h
// UI field definitions for passwordless credential provider
// Note: No password field - this is intentionally passwordless!

#pragma once

#include <credentialprovider.h>
#include <windows.h>

// Field IDs - Passwordless flow
enum FIELD_ID
{
    FID_LOGO = 0,           // Tile image
    FID_LARGE_TEXT,         // Title text
    FID_SMALL_TEXT,         // Status/instruction text  
    FID_USERNAME,           // Username input
    FID_OTP,                // OTP code input (shown after username validation)
    FID_SUBMIT,             // Submit button
    FID_NUM_FIELDS
};

// Field state pair
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// Field descriptors - Define the UI elements
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgFieldDescriptors[] =
{
    { FID_LOGO,       CPFT_TILE_IMAGE,    L"Logo",                      CPFG_CREDENTIAL_PROVIDER_LOGO },
    { FID_LARGE_TEXT, CPFT_LARGE_TEXT,    L"Authentik Passwordless",    CPFG_CREDENTIAL_PROVIDER_LABEL },
    { FID_SMALL_TEXT, CPFT_SMALL_TEXT,    L"Sign in with your identity", CPFG_CREDENTIAL_PROVIDER_LABEL },
    { FID_USERNAME,   CPFT_EDIT_TEXT,     L"Username",                  CPFG_NONE },
    { FID_OTP,        CPFT_PASSWORD_TEXT, L"Verification Code",         CPFG_NONE },
    { FID_SUBMIT,     CPFT_SUBMIT_BUTTON, L"Sign in",                   CPFG_NONE },
};

// Initial field states - Username step
static const FIELD_STATE_PAIR s_rgFieldStatePairsUnlock[] =
{
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LOGO
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SMALL_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_USERNAME - focused initially
    { CPFS_HIDDEN, CPFIS_NONE },                       // FID_OTP - hidden until needed
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SUBMIT
};

// Field states for logon scenario
static const FIELD_STATE_PAIR s_rgFieldStatePairsLogon[] =
{
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LOGO
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SMALL_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_USERNAME - focused initially
    { CPFS_HIDDEN, CPFIS_NONE },                       // FID_OTP - hidden until needed
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SUBMIT
};

// Helper function to allocate and copy field descriptor
inline HRESULT FieldDescriptorCoAllocCopy(
    const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR& rcpfd,
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd)
{
    HRESULT hr;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd = 
        (CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*)CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR));

    if (pcpfd)
    {
        pcpfd->dwFieldID = rcpfd.dwFieldID;
        pcpfd->cpft = rcpfd.cpft;
        pcpfd->guidFieldType = rcpfd.guidFieldType;

        if (rcpfd.pszLabel)
        {
            hr = SHStrDupW(rcpfd.pszLabel, &pcpfd->pszLabel);
        }
        else
        {
            pcpfd->pszLabel = nullptr;
            hr = S_OK;
        }

        if (SUCCEEDED(hr))
        {
            *ppcpfd = pcpfd;
        }
        else
        {
            CoTaskMemFree(pcpfd);
        }
    }
    else
    {
        hr = E_OUTOFMEMORY;
    }

    return hr;
}
