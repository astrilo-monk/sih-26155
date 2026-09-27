# Written for NetAuditAI tests: an Azure NSG that lets the internet in
resource "azurerm_network_security_group" "web" {
  name                = "web-nsg"
  location            = "westeurope"
  resource_group_name = azurerm_resource_group.main.name

  security_rule {
    name                       = "ssh-any"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_rule" "any_any" {
  name                        = "allow-all"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = azurerm_resource_group.main.name
  network_security_group_name = azurerm_network_security_group.web.name
}
