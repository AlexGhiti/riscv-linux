// SPDX-License-Identifier: GPL-2.0+
/*
 * Reset driver for DA9063 PMIC series
 *
 * Author: Alexandre Ghiti, Canonical
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/reboot.h>
#include <linux/platform_device.h>
#include <linux/regmap.h>
#include <linux/mfd/da9063/core.h>
#include <linux/mfd/da9063/registers.h>

struct da9063_reset {
	struct da9063 *da9063;
	struct notifier_block nb;
};

static struct da9063_reset da9063_rst;

static int da9063_restart_notify(struct notifier_block *this,
				 unsigned long mode, void *cmd)
{
	regmap_write(da9063_rst.da9063->regmap, DA9063_REG_PAGE_CON, 0x00);
	regmap_write(da9063_rst.da9063->regmap, DA9063_REG_CONTROL_F, 0x04);
	regmap_write(da9063_rst.da9063->regmap, DA9063_REG_CONTROL_A, 0x68);

	return NOTIFY_DONE;
}

static int da9063_reset_probe(struct platform_device *pdev)
{
	struct da9063 *da9063 = dev_get_drvdata(pdev->dev.parent);
	u32 priority;
	int ret;

	da9063_rst.da9063 = da9063;
	da9063_rst.nb.notifier_call = da9063_restart_notify;
	da9063_rst.nb.priority = 128;

	ret = of_property_read_u32(pdev->dev.of_node, "priority", &priority);
	if (!ret) {
		if (priority > 255)
			dev_err(&pdev->dev, "Invalid priority property: %u\n",
				priority);
		else
			da9063_rst.nb.priority = priority;
	}

	return register_restart_handler(&da9063_rst.nb);
}

static int da9063_reset_remove(struct platform_device *pdev)
{
	return unregister_restart_handler(&da9063_rst.nb);
}

static struct platform_driver da9063_reset_driver = {
	.driver = {
		.name = DA9063_DRVNAME_RESET,
	},
	.probe = da9063_reset_probe,
	.remove = da9063_reset_remove,
};

static int __init da9063_reset_init(void)
{
	return platform_driver_register(&da9063_reset_driver);
}
subsys_initcall(da9063_reset_init);

static void __exit da9063_reset_cleanup(void)
{
	platform_driver_unregister(&da9063_reset_driver);
}
module_exit(da9063_reset_cleanup);

MODULE_AUTHOR("Alexandre Ghiti <alexandre.ghiti@canonical.com>");
MODULE_DESCRIPTION("DA9063 reset driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" DA9063_DRVNAME_RESET);
