# Synthetic Customer Registration Fixture

This synthetic fixture describes a customer registration flow for automated
threat-modeling tests. It is not production data.

- Customer submits registration data to the registration process.
- The registration process stores the customer record and sends activation
  data to a notification process.
- The notification process sends the recipient and activation message to the
  vendor email service and receives delivery status.
- Vendor retention and deletion behavior are intentionally unknown.
