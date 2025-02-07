package net.icebns.rbac_shiro;

import java.security.spec.AlgorithmParameterSpec;

public class ECGenParameterSpec implements AlgorithmParameterSpec {
    private final String name;

    /**
     * 使用标准的（或预定义的）名称 stdName创建用于 EC 参数生成的参数规范，
     * 以便生成相应的（预计算的）椭圆曲线域参数。
     * 有关受支持的名称列表，请参考将使用其实现的供应商的文档。
     *
     * @param stdName 要生成的 EC 域参数的标准名称。
     * @throws NullPointerException 如果 stdName为 null。
     */
    public ECGenParameterSpec(String stdName) {
        if (stdName == null) {
            throw new NullPointerException("stdName cannot be null");
        }
        this.name = stdName;
    }

    /**
     * 返回要生成的 EC 域参数的标准名称或预定义名称。
     *
     * @return 标准名称或预定义名称。
     */
    public String getName() {
        return name;
    }
}