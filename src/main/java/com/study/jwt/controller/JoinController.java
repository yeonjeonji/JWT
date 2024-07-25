package com.study.jwt.controller;

import com.study.jwt.dto.JoinDto;
import com.study.jwt.service.JoinService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class JoinController {

    private  final JoinService joinService;


    //생성자주입
    public JoinController(JoinService joinService) {
        this.joinService = joinService;
    }


    @PostMapping("/join")
    public String joinProcess(JoinDto joinDto) {

        joinService.joinProcess(joinDto);

        return "ok";
    }
}
