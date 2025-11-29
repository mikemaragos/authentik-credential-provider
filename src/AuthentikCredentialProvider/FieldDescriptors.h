// FieldDescriptors.h
// Definitions for credential provider fields

#pragma once

#include <windows.h>
#include <credentialprovider.h>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

// Field IDs
enum FIELD_ID
{
    FID_LOGO = 0,
    FID_LARGE_TEXT,
    FID_SMALL_TEXT,
    FID_USERNAME,
    FID_OTP,
    FID_SUBMIT,
    FID_NUM_FIELDS
};

// Field state pair
struct FIELD_STATE_PAIR
{
    CREDENTIAL_PROVIDER_FIELD_STATE cpfs;
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE cpfis;
};

// Field descriptors
// Note: For CPFT_EDIT_TEXT, pszLabel appears as gray placeholder text
static const CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR s_rgFieldDescriptors[] =
{
    { FID_LOGO,       CPFT_TILE_IMAGE,    const_cast<LPWSTR>(L"Logo"),                         CPFG_CREDENTIAL_PROVIDER_LOGO },
    { FID_LARGE_TEXT, CPFT_LARGE_TEXT,    const_cast<LPWSTR>(L"Authentik Passwordless"),       CPFG_CREDENTIAL_PROVIDER_LABEL },
    { FID_SMALL_TEXT, CPFT_SMALL_TEXT,    const_cast<LPWSTR>(L"Sign in with OTP"),             GUID_NULL },
    { FID_USERNAME,   CPFT_EDIT_TEXT,     const_cast<LPWSTR>(L"Username"),                     GUID_NULL },
    { FID_OTP,        CPFT_PASSWORD_TEXT, const_cast<LPWSTR>(L"One-time code"),                GUID_NULL },
    { FID_SUBMIT,     CPFT_SUBMIT_BUTTON, const_cast<LPWSTR>(L"Sign in"),                      GUID_NULL },
};

// Initial field state pairs
static const FIELD_STATE_PAIR s_rgFieldStatePairs[] =
{
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LOGO
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_LARGE_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_NONE },     // FID_SMALL_TEXT
    { CPFS_DISPLAY_IN_SELECTED_TILE, CPFIS_FOCUSED },  // FID_USERNAME
    { CPFS_HIDDEN, CPFIS_NONE },                       // FID_OTP (hidden initially)
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
            pcpfd->pszLabel = NULL;
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
