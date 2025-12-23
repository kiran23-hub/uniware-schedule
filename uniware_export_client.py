# uniware_export_client.py
"""
Uniware export helper (updated for GitHub Actions).
- No local CSV files: download CSV into memory and build a combined DataFrame.
- Multi-facility run, final DataFrame pushed to Google Sheet.
"""
import numpy as np
import pandas as pd
import requests
import time
import os
from io import StringIO
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from datetime import datetime
import pytz




# ---------- CONFIG ----------
BASE_URL = "https://zilo.unicommerce.com/"
OAUTH_TOKEN_PATH = "/oauth/token"

CREATE_EXPORT_JOB_PATH = "/services/rest/v1/export/job/create"
GET_EXPORT_JOB_PATH = "/services/rest/v1/export/job/status"


CLIENT_ID = "sparsh.v@zilo.one"
CLIENT_SECRET = "SeMxx9FZvW6pV!@"

REQUEST_TIMEOUT = 20

# Optional facility header (overridden per facility in main)
FACILITY: Optional[str] = "zilo"

MAX_POLL_SECONDS = 240
POLL_BASE_SEC = 3

# Delay before polling (seconds)
DELAY_BEFORE_POLL_SECONDS = 1 * 60
# -----------------------------------------------

def get_access_token() -> str:
    url = BASE_URL.rstrip("/") + OAUTH_TOKEN_PATH
    params = {
        "grant_type": "password",
        "client_id": "my-trusted-client",
        "username": CLIENT_ID,
        "password": CLIENT_SECRET
    }
    r = requests.get(url, params=params, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    data = r.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError(f"No access_token in token response: {data}")
    print("[token] obtained access_token (len {})".format(len(token)))
    return token

def _request_with_token(method: str, url: str, headers: Optional[dict] = None,
                        retry_on_401: bool = True, **kwargs) -> requests.Response:
    hdrs = dict(headers or {})
    token = get_access_token()
    hdrs["Authorization"] = f"bearer {token}"
    if FACILITY:
        hdrs["Facility"] = FACILITY
    resp = requests.request(method, url, headers=hdrs, timeout=REQUEST_TIMEOUT, **kwargs)
    if retry_on_401 and resp.status_code == 401:
        token = get_access_token()
        hdrs["Authorization"] = f"bearer {token}"
        resp = requests.request(method, url, headers=hdrs, timeout=REQUEST_TIMEOUT, **kwargs)
    resp.raise_for_status()
    return resp

def build_today_date_filter(filter_id: str = "1",
                            filter_text: str = "Created In Date Range") -> List[dict]:
    local_now = datetime.now().astimezone()
    local_start = local_now.replace(hour=0, minute=0, second=1, microsecond=0)

    utc_start = local_start.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    utc_end = local_now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

    return [
        {
            "id": filter_id,
            "text": filter_text,
            "dateRange": {
                "start": utc_start,
                "end": utc_end
            }
        }
    ]

def create_export_job(export_job_type_name: str,
                      export_columns: List[str],
                      export_filters: Optional[list] = None,
                      frequency: str = "ONETIME",
                      extra_payload: Optional[dict] = None) -> Tuple[str, Optional[str]]:
    url = BASE_URL.rstrip("/") + CREATE_EXPORT_JOB_PATH
    headers = {"Content-Type": "application/json"}
    body = {
        "exportJobTypeName": export_job_type_name,
        "exportColums": export_columns,
        "frequency": frequency
    }
    if export_filters:
        body["exportFilters"] = export_filters
    if extra_payload:
        body.update(extra_payload)

    print("[create_export_job] POST ->", url)
    print("[create_export_job] payload keys:", list(body.keys()))
    print(body)
    resp = _request_with_token("POST", url, headers=headers, json=body)
    j = resp.json()
    print("[create_export_job] response:", j)
    if "successful" in j and not j.get("successful"):
        raise RuntimeError(f"Create export job returned unsuccessful: {j}")
    job_code = j.get("jobCode")
    export_job_id = j.get("exportJobId")
    if not job_code:
        raise RuntimeError(f"No jobCode returned: {j}")
    print(f"[create_export_job] created jobCode={job_code}, exportJobId={export_job_id}")
    return job_code, export_job_id

def get_export_status(job_code: str) -> dict:
    url = BASE_URL.rstrip("/") + GET_EXPORT_JOB_PATH
    headers = {"Content-Type": "application/json"}
    body = {"jobCode": job_code}
    resp = _request_with_token("POST", url, headers=headers, json=body)
    j = resp.json()
    print(f"[get_export_status] status for {job_code} -> {j.get('status')!r}, "
          f"filePath={'PRESENT' if j.get('filePath') else 'MISSING'}")
    return j

def wait_for_completion(job_code: str,
                        max_seconds: int = MAX_POLL_SECONDS,
                        base_interval: int = POLL_BASE_SEC) -> dict:
    START_SUCCESS = {"SUCCESS", "SUCCESSFUL", "COMPLETED", "COMPLETE", "DONE"}
    start = time.time()
    attempt = 0
    interval = base_interval

    print(f"[wait_for_completion] start polling job {job_code} (timeout {max_seconds}s)")
    while True:
        attempt += 1
        status_json = get_export_status(job_code)
        status_raw = (status_json.get("status") or "")
        status = status_raw.strip().upper()
        file_path = status_json.get("filePath")

        print(f"[wait_for_completion] attempt {attempt}, status={status_raw!r}, "
              f"filePath={'PRESENT' if file_path else 'MISSING'}")

        if status in START_SUCCESS and file_path:
            print(f"[wait_for_completion] job {job_code} finished with status={status_raw}; filePath available.")
            return status_json

        if status in START_SUCCESS and not file_path:
            print(f"[wait_for_completion] job {job_code} status={status_raw} but filePath missing — waiting up to 60s...")
            small_wait_start = time.time()
            while time.time() - small_wait_start < 60:
                time.sleep(3)
                status_json = get_export_status(job_code)
                file_path = status_json.get("filePath")
                if file_path:
                    print("[wait_for_completion] filePath became available.")
                    return status_json
            print("[wait_for_completion] filePath still missing after short wait; returning status JSON.")
            return status_json

        if status_json.get("successful") is False and status_json.get("errors"):
            raise RuntimeError(f"Export job failed: {status_json.get('errors')}")

        elapsed = time.time() - start
        if elapsed > max_seconds:
            raise TimeoutError(f"Timed out waiting for export job {job_code} after {max_seconds} seconds. "
                               f"Last status: {status_raw}")

        print(f"[wait_for_completion] sleeping {interval}s before next poll...")
        time.sleep(interval + (attempt % 3))
        interval = min(interval * 1.8, 30)

def download_csv_to_df(file_path: str) -> pd.DataFrame:
    """
    Downloads CSV from Uniware file_path URL into a pandas DataFrame (no local file saved).
    """
    headers = {}
    token = get_access_token()
    headers["Authorization"] = f"bearer {token}"
    if FACILITY:
        headers["Facility"] = FACILITY

    print(f"[download_csv_to_df] downloading {file_path} ...")
    resp = requests.get(file_path, headers=headers, timeout=REQUEST_TIMEOUT)
    if resp.status_code == 401:
        token = get_access_token()
        headers["Authorization"] = f"bearer {token}"
        resp = requests.get(file_path, headers=headers, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()

    # Use text + StringIO so nothing is written to disk
    csv_text = resp.text
    df = pd.read_csv(StringIO(csv_text))
    print(f"[download_csv_to_df] loaded dataframe with shape {df.shape}")
    return df

def run_export_and_get_df(export_job_type_name: str,
                          export_columns: List[str],
                          export_filters: Optional[list] = None,
                          frequency: str = "ONETIME",
                          wait_for_file: bool = True,
                          extra_payload: Optional[dict] = None) -> pd.DataFrame:
    """
    Create export job, wait for file, download CSV into DataFrame, and return it.
    """
    job_code, export_job_id = create_export_job(export_job_type_name, export_columns,
                                                export_filters, frequency, extra_payload)
    print(f"[run_export_and_get_df] created jobCode={job_code}, exportJobId={export_job_id}")

    if not wait_for_file:
        return pd.DataFrame()

    if DELAY_BEFORE_POLL_SECONDS > 0:
        print(f"[run_export_and_get_df] waiting {DELAY_BEFORE_POLL_SECONDS} seconds before polling...")
        time.sleep(DELAY_BEFORE_POLL_SECONDS)

    status_json = wait_for_completion(job_code)
    file_path = status_json.get("filePath")
    if not file_path:
        raise RuntimeError(f"No filePath returned in status: {status_json}")

    df = download_csv_to_df(file_path)
    return df

# ---------------- MAIN (multi-facility, combined DF, push to Sheets) ----------------
if __name__ == "__main__":

    FACILITIES = [
        "Zilo_MUM_Ghatkopar",
        "zilo"  # add/remove as needed
    ]

    EXPORT_TYPE = "Sale Orders"
    EXPORT_COLUMNS = [
        "soicode","displayorderCode","reversePickupCode","reversePickupCreatedDate","reversePickupReason","notificationEmail",
        "notificationMobile","requireCustomization","cod","shippingAddressId","category","invoiceCode","invoiceCreated","ewbNo",
        "ewbDate","ewbValidTill","shippingAddressName","shippingAddressLine1","shippingAddressLine2","shippingAddressCity",
        "shippingAddressState","shippingAddressCountry","shippingAddressPincode","shippingAddressLatitude","shippingAddressLongitude",
        "shippingAddressPhone","billingAddressId","billingAddressName","billingAddressLine1","billingAddressLine2","billingAddressCity",
        "billingAddressState","billingAddressCountry","billingAddressPincode","billingAddressLatitude","billingAddressLongitude",
        "billingAddressPhone","shippingMethod","skuCode","channelProductId","itemTypeName","itemTypeColor","itemTypeSize",
        "itemTypeBrand","channel","itemRequireCustomization","giftWrap","giftMessage","hsnCode","maxRetailPrice","totalPrice",
        "sellingPrice","costPrice","prepaidAmount","subtotal","discount","gstTaxTypeCode","cgst","igst","sgst","utgst","cess",
        "cgstrate","igstrate","sgstrate","utgstrate","cessrate","TCSAmount","tax","taxValue","voucherCode","shippingCharges",
        "shippingMethodCharges","cashOnDeliveryCharges","giftWrapCharges","packetNumber","displayOrderDateTime","saleOrderCode",
        "onhold","status","priority","currency","currencyConversionRate","SoiStatus","cancellationReason","shippingProvider",
        "shippingCourier","shippingArrangedBy","ShippingPackageCode","ShippingPackageCreationDate","shippingPackageStatusCode",
        "shippingPackageTypeCode","shippingPackageLength","shippingPackageWidth","shippingPackageHeight","deliveryTime",
        "TrackingNumber","dispatchDate","facility","returnedDate","returnReason","returnRemarks","created","updated",
        "combinationIdentifier","combinationDescription","transferPrice","itemCode","imei","actualWeight","gsttin",
        "Cgsttin","tin","paymentInstrc","fulfillmentTat","ajustmentInSellingPrice","ajustmentInDiscount","storeCredit",
        "irn","acknowledgementNumber","bundleSkuCode","skuName","batchCode","vendorBatchNumber","sellerSkuCode","itemTypeEAN",
        "shippingCourierStatus","shippingTrackingStatus","itemSealId","parentSaleOrderCode","itemTag","shipmentTag",
        "saleOrderCustomFields_DeliverySlotType","saleOrderCustomFields_Delivery_Date","saleOrderCustomFields_Delivery_Time",
        "saleOrderCustomFields_Delivery_Type","saleOrderCustomFields_pinpointly_latitude","saleOrderCustomFields_pinpointly_longitude"
    ]

    EXPORT_FILTERS = [
        {
            "id": "addedOn",
            "dateRange": {"textRange": "TODAY"}
        }
    ]

    dfs = []

    for fac in FACILITIES:
        print(f"\n================ RUNNING EXPORT FOR FACILITY: {fac} ================\n")
        FACILITY = fac  # switch facility dynamically

        try:
            df_fac = run_export_and_get_df(
                EXPORT_TYPE,
                EXPORT_COLUMNS,
                export_filters=EXPORT_FILTERS,
                wait_for_file=True
            )
            df_fac["facility_source"] = fac
            dfs.append(df_fac)
            print(f"[SUCCESS] Completed for {fac} | rows: {len(df_fac)}")

        except Exception as e:
            print(f"[ERROR] Failed for facility {fac}: {e}")


    if not dfs:
        raise RuntimeError("No dataframes were returned from any facility.")

    Final_df = pd.concat(dfs, ignore_index=True)
    column_list = ['Sale Order Item Code',
 'Display Order Code',
 'Reverse Pickup Code',
 'Reverse Pickup Created Date',
 'Reverse Pickup Reason',
 'Notification Email',
 'Notification Mobile',
 'Require Customization',
 'COD',
 'Shipping Address Id',
 'Category',
 'Invoice Code',
 'Invoice Created',
 'EWayBill No',
 'EWayBill Date',
 'EWayBill Valid Till',
 'Shipping Address Name',
 'Shipping Address Line 1',
 'Shipping Address Line 2',
 'Shipping Address City',
 'Shipping Address State',
 'Shipping Address Country',
 'Shipping Address Pincode',
 'Shipping Address Latitude',
 'Shipping Address Longitude',
 'Shipping Address Phone',
 'Billing Address Id',
 'Billing Address Name',
 'Billing Address Line 1',
 'Billing Address Line 2',
 'Billing Address City',
 'Billing Address State',
 'Billing Address Country',
 'Billing Address Pincode',
 'Billing Address Latitude',
 'Billing Address Longitude',
 'Billing Address Phone',
 'Shipping Method',
 'Item SKU Code',
 'Channel Product Id',
 'Item Type Name',
 'Item Type Color',
 'Item Type Size',
 'Item Type Brand',
 'Channel Name',
 'SKU Require Customization',
 'Gift Wrap',
 'Gift Message',
 'HSN Code',
 'MRP',
 'Total Price',
 'Selling Price',
 'Cost Price',
 'Prepaid Amount',
 'Subtotal',
 'Discount',
 'GST Tax Type Code',
 'CGST',
 'IGST',
 'SGST',
 'UTGST',
 'CESS',
 'CGST Rate',
 'IGST Rate',
 'SGST Rate',
 'UTGST Rate',
 'CESS Rate',
 'TCS Amount',
 'Tax %',
 'Tax Value',
 'Voucher Code',
 'Shipping Charges',
 'Shipping Method Charges',
 'COD Service Charges',
 'Gift Wrap Charges',
 'Packet Number',
 'Order Date as dd/mm/yyyy hh:MM:ss',
 'Sale Order Code',
 'On Hold',
 'Sale Order Status',
 'Priority',
 'Currency',
 'Currency Conversion Rate',
 'Sale Order Item Status',
 'Cancellation Reason',
 'Shipping provider',
 'Shipping Courier',
 'Shipping Arranged By',
 'Shipping Package Code',
 'Shipping Package Creation Date',
 'Shipping Package Status Code',
 'Shipping Package Type',
 'Length(mm)',
 'Width(mm)',
 'Height(mm)',
 'Delivery Time',
 'Tracking Number',
 'Dispatch Date',
 'Facility',
 'Return Date',
 'Return Reason',
 'Return Remarks',
 'Created',
 'Updated',
 'Combination Identifier',
 'Combination Description',
 'Transfer Price',
 'Item Code',
 'IMEI',
 'Weight',
 'GSTIN',
 'Customer GSTIN',
 'TIN',
 'Payment Instrument',
 'Fulfillment TAT',
 'Adjustment In Selling Price',
 'Adjustment In Discount',
 'Store Credit',
 'IRN',
 'Acknowledgement Number',
 'Bundle SKU Code Number',
 'SKU Name',
 'Batch Code',
 'Vendor Batch Number',
 'Seller SKU Code',
 'Item Type EAN',
 'Shipping Courier Status',
 'Shipping Tracking Status',
 'Item Seal Id',
 'Parent Sale Order Code',
 'Item Tag',
 'Shipment Tag',
 'Delivery Slot Type',
 'Delivery Date',
 'Delivery Time.1',
 'Delivery Type',
 'pin pointly latitude',
 'pinpointly longitude',
 'Channel Shipping',
 'Item Details']

    # Optional: ensure this datetime column is proper dtype if present
    if "Order Date as dd/mm/yyyy hh:MM:ss" in Final_df.columns:
        Final_df["Order Date as dd/mm/yyyy hh:MM:ss"] = pd.to_datetime(
            Final_df["Order Date as dd/mm/yyyy hh:MM:ss"], errors="coerce"
        )

    print("Combined Final_df shape:", Final_df.shape)

    # ---------- Push Final_df to Google Sheet ----------
    import gspread
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from gspread_dataframe import set_with_dataframe

    SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]
    CREDENTIALS_JSON = "Credentials.json"
    TOKEN_JSON = "token.json"

    def get_credentials():
        creds = None
        if os.path.exists(TOKEN_JSON):
            creds = Credentials.from_authorized_user_file(TOKEN_JSON, SCOPES)
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
        if not creds or not creds.valid:
            flow = InstalledAppFlow.from_client_secrets_file(CREDENTIALS_JSON, SCOPES)
            creds = flow.run_local_server(port=0)
            with open(TOKEN_JSON, "w") as token_file:
                token_file.write(creds.to_json())
        return creds

    creds = get_credentials()
    gc = gspread.authorize(creds)

    SHEET_ID = "1N5A5tOSpZeoLyiFwjNJQBUw7GIbrdXfP-hawKqQpHdk"
    ws = gc.open_by_key(SHEET_ID)
    Sheet = ws.worksheet("Today")

    # Clear sheet and write Final_df
    Sheet.batch_clear(["A:EJ"])
    set_with_dataframe(Sheet, Final_df[column_list])
    print("Final_df written to Google Sheet 'Today'.")
# ---------- Update timestamp in PvA sheet ----------
ist = pytz.timezone("Asia/Kolkata")
timestamp = datetime.now(ist).strftime("Last Updated - %H:%M")

pva_sheet = ws.worksheet("PvA")
pva_sheet.update_acell("F1", timestamp) 

