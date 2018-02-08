package com.xiewei.modules.webservice;

import java.io.IOException;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.activiti.engine.repository.Model;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/ws/user")
public interface UserService {
	
	@RequestMapping(value="/login", method = RequestMethod.GET, produces = "application/json;charset=UTF-8")
	@ResponseBody
	public Map<String,Object> login(String userName,String pwd);
	
	@RequestMapping(value="/register", method = RequestMethod.POST, produces = "application/json;charset=UTF-8")
	@ResponseBody
	public Map<String,Object> register(String loginname,String idcard,String name,String mobile,String password);
	
	@RequestMapping(value="/update", method = RequestMethod.PUT, produces = "application/json;charset=UTF-8")
	@ResponseBody
	public Map<String,Object> update(String userName,String pwd);
	
	
	/**
	 * 微信支付
	 * @param body
	 * @param out_trade_no
	 * @param total_fee
	 * @param spbill_create_ip
	 * @return
	 */
	@RequestMapping(value="/wechatpay", method = RequestMethod.GET, produces = "application/json;charset=UTF-8")
	@ResponseBody
	public Map<String, Object> wechatpay(String body,String out_trade_no,int total_fee,String spbill_create_ip);
	

	/**
	 * 微信支付成功回调
	 * @param model
	 * @param request
	 * @param response
	 * @param session
	 * @throws IOException
	 */
	@RequestMapping(value ="/goback",method = RequestMethod.GET, produces = "application/json;charset=UTF-8")
	@ResponseBody
	public void goback(Model model,HttpServletRequest request,HttpServletResponse response,
			HttpSession session) throws IOException;
	
	
	/**
	 * 支付宝支付
	 * @param outtradeno
	 * @return
	 */
	@RequestMapping(value="/alipay", method = RequestMethod.GET, produces = "application/json;charset=UTF-8")
	@ResponseBody
	public Map<String,Object> alipay(String subject,String out_trade_no,String total_amount);
	
	/**
	 * 支付宝成功回调
	 */
	@RequestMapping(value="/alipaynotify", method = RequestMethod.POST, produces = "application/json;charset=UTF-8")
	@ResponseBody
	public void alipaynotify(HttpServletRequest request);
	
}
