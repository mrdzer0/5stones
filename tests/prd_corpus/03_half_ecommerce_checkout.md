# Product Requirements Document

> ID: PRD-EC-003
> Completeness: Half
> Product type: Consumer checkout web application
> Owner: Commerce Product Team
> Release: Iteration 12 synthetic sample
> Expected threat-model scope: Cart, checkout, payment, inventory, order status

## 1. Overview

The storefront allows a shopper to browse products, add them to a cart, enter a delivery address, pay, and see order status. Merchants can update product stock and view orders belonging to their store. The first release uses a hosted payment gateway and a shipping partner.

The PRD intentionally does not define the authentication mechanism, order retention period, webhook signature process, or the authorization boundary between merchants. These are release-blocking questions, not confirmed vulnerabilities.

## Actors and roles

- **Shopper**: browses products, creates a cart, submits checkout, and views their order.
- **Merchant operator**: manages stock and views orders for a store.
- **Support agent**: may help a shopper find an order; exact access is not defined.
- **Payment gateway**: accepts a hosted payment session and sends a payment result.
- **Shipping partner**: receives address and parcel data to create a shipment.

## User journeys

### UC-01 Shopper creates a cart

Actor: Shopper

Steps:

1. Shopper selects a product and quantity in the Storefront.
2. Storefront sends product ID and quantity to the Checkout API.
3. Checkout API reads price and stock from the Catalog and Inventory service.
4. Checkout API creates a cart and returns a cart reference.

Data: Product ID, quantity, displayed price, cart reference.

Evidence locator: User journeys / UC-01 Shopper creates a cart.

### UC-02 Shopper checks out

Actor: Shopper

Preconditions: Cart exists and stock is available.

Steps:

1. Shopper submits delivery name, phone, address, and cart reference.
2. Checkout API calculates shipping and creates an order in `pending_payment` state.
3. Checkout API creates a hosted checkout session at the Payment gateway.
4. Shopper completes payment on the hosted page.
5. Payment gateway sends a payment result to the Checkout API.
6. Checkout API marks the order paid and asks the Inventory service to reserve stock.
7. Checkout API sends address and parcel information to the Shipping partner.

Data: Delivery name, phone, address, cart, order, payment session, payment result, parcel data.

Evidence locator: User journeys / UC-02 Shopper checks out.

### UC-03 Merchant updates stock

Actor: Merchant operator

Steps:

1. Merchant operator opens the merchant console.
2. Console sends product and stock quantity to the Inventory service.
3. Inventory service updates stock and records the operator identity.

Data: Product ID, stock quantity, merchant identity, update timestamp.

Evidence locator: User journeys / UC-03 Merchant updates stock.

## Components and trust boundaries

| Zone | Components | Trust boundary |
| --- | --- | --- |
| Public-facing | Storefront, Checkout API | Internet boundary |
| Internal application | Catalog service, Inventory service, Order service | Organization application boundary |
| Data stores | Cart store, Order database, Merchant store | Data boundary; exact isolation not defined |
| External systems | Payment gateway, Shipping partner | Third-party boundary |
| Workforce | Merchant console, possible Support console | Privileged access boundary; support scope TBD |

## Data flows

| Flow | Source -> destination | Protocol | Data | Evidence |
| --- | --- | --- | --- | --- |
| F-01 | Shopper -> Storefront | HTTPS | Product selection, address, checkout form | UC-01, UC-02 |
| F-02 | Storefront -> Checkout API | HTTPS | Product ID, quantity, cart, order request | UC-01, UC-02 |
| F-03 | Checkout API -> Catalog/Inventory | Internal API | Price, stock, reservation | UC-01, UC-02 |
| F-04 | Checkout API -> Order database | Internal API | Pending order and address | UC-02 |
| F-05 | Checkout API -> Payment gateway | Hosted HTTPS | Payment session | UC-02 |
| F-06 | Payment gateway -> Checkout API | Webhook, details TBD | Payment result | UC-02 |
| F-07 | Checkout API -> Shipping partner | HTTPS, details TBD | Address and parcel data | UC-02 |
| F-08 | Merchant console -> Inventory service | HTTPS | Stock update | UC-03 |

## Data inventory

| Data | Classification | Store or transit | Known requirement |
| --- | --- | --- | --- |
| Cart and product choice | Business data | Cart store | Expiration is TBD |
| Name, phone, delivery address | Personal data | Order database and Shipping partner | Minimize and protect; retention TBD |
| Payment session and result | Payment metadata | Checkout API and gateway | Product should not store card number |
| Merchant identity and stock | Confidential business data | Merchant store | Tenant/store scope is TBD |

## External systems

- Payment gateway: hosted collection and payment callback. Signature verification and replay window are not described.
- Shipping partner: receives delivery address and parcel data. Data deletion and partner access are not described.

## Functional requirements

1. A cart can be converted into one order.
2. A paid order reserves inventory.
3. An order cannot be shipped before payment succeeds.
4. A merchant sees only products and orders for their store.
5. The shopper can see order status after checkout.

## Security and privacy requirements

- Checkout and payment pages use HTTPS.
- The payment gateway must not send raw card data to the product.
- Order status must not be guessable from a sequential ID.
- Address data should be sent only to the Shipping partner when delivery is required.

The following controls are not yet specified: customer authentication, merchant authorization, webhook signature validation, idempotency for callbacks, exact rate limits, address retention, deletion propagation, support-agent access, and refund approval.

## Open questions and assumptions

- **TBD**: Is the shopper authenticated, or is checkout guest-only?
- **TBD**: How does the API prove that a merchant belongs to the store in the request?
- **TBD**: How are Payment gateway callbacks signed and replay-protected?
- **TBD**: What happens if the callback is delivered twice or after a timeout?
- **TBD**: How long are address, cart, and order records retained?
- **TBD**: Can Support agents view or change an order, and who approves refunds?
- Assumption: the Payment gateway is the system of record for card data.

## Acceptance criteria

1. A paid order cannot reserve more stock than is available.
2. Repeated payment callbacks do not create duplicate order side effects.
3. A shopper cannot read another shopper's order by changing a reference.
4. A merchant cannot update another merchant's stock.
5. The analysis output explicitly marks the unresolved authentication, callback, authorization, and retention decisions as deferred.
