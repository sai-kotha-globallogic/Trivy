resource "azurerm_resource_group" "tf_example" {
  name     = "terraform-state"
  location = "East US"
}

resource "azurerm_storage_account" "terraform_state" {
  name = "tfstoragedevsecopsanil"
  resource_group_name = azurerm_resource_group.tf_example.name
  location = azurerm_resource_group.tf_example.location
  account_tier  = "Standard"
  account_replication_type = "GRS"

  tags = {
    environment = "shared"
    team        = "devsecops"
  }
}

resource "azurerm_resource_group" "tf_example_2" {
  name     = "terraform-state-2"
  location = "Central US"
}
